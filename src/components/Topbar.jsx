import React, { useState } from 'react';
import { ShieldCheck, Server, FileText, CheckCircle2, Lock, Unlock, Terminal, Activity, RefreshCw, AlertTriangle, RotateCcw, Upload } from 'lucide-react';

export function Topbar({ activeTab, setActiveTab, caStatus, onRefreshStatus, onOpenResetWizard }) {
  const [showUnlockModal, setShowUnlockModal] = useState(false);
  const [unlockPassphrase, setUnlockPassphrase] = useState('');
  const [unlockDuration, setUnlockDuration] = useState(15);
  const [unlockLoading, setUnlockLoading] = useState(false);
  const [unlockError, setUnlockError] = useState(null);

  // CA Recovery & Operations Modal State
  const [showOpsModal, setShowOpsModal] = useState(false);
  const [opsTab, setOpsTab] = useState('replace'); // 'replace' or 'reset'
  
  // Replace Cert Form State
  const [replaceCertPem, setReplaceCertPem] = useState('');
  const [replaceKeyPem, setReplaceKeyPem] = useState('');
  const [replacePassphrase, setReplacePassphrase] = useState('');
  const [replaceLoading, setReplaceLoading] = useState(false);
  const [replaceError, setReplaceError] = useState(null);

  // Reset Form State
  const [resetPassphrase, setResetPassphrase] = useState('');
  const [resetLoading, setResetLoading] = useState(false);
  const [resetError, setResetError] = useState(null);

  // CRL Config State
  const [crlUrlInput, setCrlUrlInput] = useState('');
  const [cdpUrlInput, setCdpUrlInput] = useState('/api/crl');
  const [crlUrlLoading, setCrlUrlLoading] = useState(false);

  const handleCrlUrlSubmit = async (e) => {
    e.preventDefault();
    setCrlUrlLoading(true);
    try {
      if (caStatus?.config?.type === 'intermediate' && crlUrlInput) {
        await fetch('/api/setup/update-crl-url', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ parentCrlUrl: crlUrlInput })
        });
      }

      if (cdpUrlInput) {
        await fetch('/api/setup/update-cdp', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ crlDistributionPoint: cdpUrlInput })
        });
      }

      alert('CRL & Distribution Point Configuration updated successfully!');
      setShowOpsModal(false);
      onRefreshStatus();
    } catch (err) {
      alert(err.message);
    } finally {
      setCrlUrlLoading(false);
    }
  };

  const handleUnlockSession = async () => {
    setUnlockLoading(true);
    setUnlockError(null);
    try {
      const res = await fetch('/api/session/unlock', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ passphrase: unlockPassphrase, durationMinutes: parseInt(unlockDuration) })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Failed to unlock session');

      setShowUnlockModal(false);
      setUnlockPassphrase('');
      onRefreshStatus();
    } catch (err) {
      setUnlockError(err.message);
    } finally {
      setUnlockLoading(false);
    }
  };

  const handleLockSession = async () => {
    try {
      await fetch('/api/session/lock', { method: 'POST' });
      onRefreshStatus();
    } catch (err) {
      console.error(err);
    }
  };

  const handleReplaceSubmit = async (e) => {
    e.preventDefault();
    setReplaceLoading(true);
    setReplaceError(null);
    try {
      const res = await fetch('/api/setup/replace-cert', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          subCaCertPem: replaceCertPem,
          subCaPrivateKeyPem: replaceKeyPem || null,
          passphrase: replacePassphrase
        })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Failed to replace Sub-CA certificate');

      alert('Sub-CA Certificate replaced successfully! Status restored to ACTIVE.');
      setShowOpsModal(false);
      onRefreshStatus();
    } catch (err) {
      setReplaceError(err.message);
    } finally {
      setReplaceLoading(false);
    }
  };

  const handleResetSubmit = async (e) => {
    e.preventDefault();
    if (!window.confirm('Are you sure you want to reset this CA? Existing certificate records will be removed, but all Audit Logs will be permanently preserved.')) {
      return;
    }

    setResetLoading(true);
    setResetError(null);
    try {
      const res = await fetch('/api/setup/reset', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ passphrase: resetPassphrase })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Failed to reset CA');

      alert('CA Configuration reset cleanly. Historical audit logs preserved.');
      setShowOpsModal(false);
      onRefreshStatus();
      if (onOpenResetWizard) onOpenResetWizard();
    } catch (err) {
      setResetError(err.message);
    } finally {
      setResetLoading(false);
    }
  };

  const handleSinglePemUpload = (e) => {
    const file = e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (event) => {
      const content = event.target.result;
      const certMatches = content.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) || [];
      if (certMatches.length > 0) setReplaceCertPem(certMatches[0]);
      const keyMatch = content.match(/-----BEGIN (?:ENCRYPTED |RSA |EC )?PRIVATE KEY-----[\s\S]*?-----END (?:ENCRYPTED |RSA |EC )?PRIVATE KEY-----/g);
      if (keyMatch && keyMatch.length > 0) setReplaceKeyPem(keyMatch[0]);
    };
    reader.readAsText(file);
  };

  return (
    <header className="topbar">
      <div className="container topbar-wrapper">
        <div className="brand">
          <div className="brand__mark">
            <i></i><i></i><i></i>
            <i></i><i></i><i></i>
            <i></i><i></i><i></i>
          </div>
          <div>
            <strong>StepCA Enterprise</strong>
            <small>step-ca Core • OPA Governed</small>
          </div>
        </div>

        <nav>
          <ul className="nav-tabs">
            <li>
              <button
                className={`nav-tab ${activeTab === 'explorer' ? 'active' : ''}`}
                onClick={() => setActiveTab('explorer')}
              >
                <Server size={15} /> Cert Explorer
              </button>
            </li>
            <li>
              <button
                className={`nav-tab ${activeTab === 'csr' ? 'active' : ''}`}
                onClick={() => setActiveTab('csr')}
              >
                <FileText size={15} /> CSR & Issuance
              </button>
            </li>
            <li>
              <button
                className={`nav-tab ${activeTab === 'opa' ? 'active' : ''}`}
                onClick={() => setActiveTab('opa')}
              >
                <ShieldCheck size={15} /> OPA Policies
              </button>
            </li>
            <li>
              <button
                className={`nav-tab ${activeTab === 'audit' ? 'active' : ''}`}
                onClick={() => setActiveTab('audit')}
              >
                <Activity size={15} /> Audit Logs
              </button>
            </li>
            <li>
              <button
                className={`nav-tab ${activeTab === 'api' ? 'active' : ''}`}
                onClick={() => setActiveTab('api')}
              >
                <Terminal size={15} /> REST API
              </button>
            </li>
          </ul>
        </nav>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <div className="sync-state" style={{ cursor: 'pointer' }} onClick={() => setShowOpsModal(true)}>
            <span className={`sync-state__dot ${caStatus?.initialized ? (caStatus.config.status === 'REVOKED' ? 'warning' : 'online') : 'warning'}`}></span>
            <div>
              <strong>
                {caStatus?.initialized
                  ? caStatus.config.status === 'REVOKED'
                    ? 'CA REVOKED (LOCKED)'
                    : caStatus.config.type === 'root' ? 'ROOT CA ONLINE' : 'SUB-CA ONLINE'
                  : 'CA UNINITIALIZED'}
              </strong>
              <small style={{ display: 'block' }}>
                {caStatus?.initialized ? `${caStatus.activeCertCount} Active Certs` : 'Setup Required'}
              </small>
            </div>
          </div>

          {caStatus?.initialized && (
            <div style={{ display: 'flex', gap: '0.4rem' }}>
              {caStatus.config.status === 'REVOKED' && (
                <button
                  className="btn btn-warning"
                  style={{ padding: '0.4rem 0.75rem', fontSize: '0.775rem' }}
                  onClick={() => setShowOpsModal(true)}
                  title="CA Revoked - Click for Recovery & Replacement Options"
                >
                  <RotateCcw size={13} /> CA Recovery
                </button>
              )}

              {caStatus.sessionUnlocked ? (
                <button
                  className="btn btn-emerald"
                  style={{ padding: '0.4rem 0.75rem', fontSize: '0.775rem' }}
                  onClick={handleLockSession}
                  title="CA Unlocked for Session (Click to Lock)"
                >
                  <Unlock size={13} /> Unlocked
                </button>
              ) : (
                <button
                  className="btn btn-secondary"
                  style={{ padding: '0.4rem 0.75rem', fontSize: '0.775rem' }}
                  onClick={() => setShowUnlockModal(true)}
                  title="Click to Unlock CA Session"
                >
                  <Lock size={13} /> Unlock
                </button>
              )}
            </div>
          )}

          {!caStatus?.initialized ? (
            <button className="btn btn-emerald" style={{ padding: '0.4rem 0.85rem', fontSize: '0.775rem' }} onClick={onOpenResetWizard}>
              <Lock size={13} /> Launch Wizard
            </button>
          ) : (
            <button
              className="btn btn-secondary"
              style={{ padding: '0.4rem 0.75rem', fontSize: '0.775rem' }}
              title="Refresh CA Status"
              onClick={onRefreshStatus}
            >
              <RefreshCw size={13} />
            </button>
          )}
        </div>
      </div>

      {/* CA SESSION UNLOCK MODAL */}
      {showUnlockModal && (
        <div className="modal-overlay">
          <div className="modal-card" style={{ maxWidth: '480px' }}>
            <div className="modal-header">
              <h3 style={{ fontFamily: 'var(--font-heading)', fontWeight: 700 }}>
                Unlock CA Key Session
              </h3>
              <button className="btn btn-secondary" style={{ padding: '0.2rem 0.5rem' }} onClick={() => setShowUnlockModal(false)}>
                ✕
              </button>
            </div>
            <div className="modal-body">
              {unlockError && (
                <div className="alert alert-danger">
                  <div>{unlockError}</div>
                </div>
              )}

              <p style={{ fontSize: '0.875rem', color: 'var(--text-muted)', marginBottom: '1rem' }}>
                Unlocking the CA session caches the decrypted signing key in memory for automated signing without typing passphrase repeatedly.
              </p>

              <div className="form-group">
                <label className="form-label">Master Passphrase</label>
                <input
                  type="password"
                  className="form-input"
                  placeholder="Enter Master Passphrase"
                  value={unlockPassphrase}
                  onChange={(e) => setUnlockPassphrase(e.target.value)}
                />
              </div>

              <div className="form-group">
                <label className="form-label">Unlock Timeout (Minutes)</label>
                <select className="form-select" value={unlockDuration} onChange={(e) => setUnlockDuration(e.target.value)}>
                  <option value={15}>15 Minutes</option>
                  <option value={60}>1 Hour</option>
                  <option value={240}>4 Hours</option>
                </select>
              </div>
            </div>
            <div className="modal-footer">
              <button className="btn btn-secondary" onClick={() => setShowUnlockModal(false)}>
                Cancel
              </button>
              <button className="btn btn-emerald" onClick={handleUnlockSession} disabled={unlockLoading}>
                {unlockLoading ? 'Unlocking...' : 'Unlock CA Session'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* CA RECOVERY & OPERATIONS MODAL */}
      {showOpsModal && (
        <div className="modal-overlay">
          <div className="modal-card" style={{ maxWidth: '640px' }}>
            <div className="modal-header">
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <RotateCcw style={{ color: 'var(--color-blue)' }} size={20} />
                <h3 style={{ fontFamily: 'var(--font-heading)', fontWeight: 700 }}>
                  CA Operations & Recovery Hub
                </h3>
              </div>
              <button className="btn btn-secondary" style={{ padding: '0.2rem 0.5rem' }} onClick={() => setShowOpsModal(false)}>
                ✕
              </button>
            </div>

            <div className="modal-body">
              <div style={{ display: 'flex', gap: '0.4rem', marginBottom: '1.25rem' }}>
                <button
                  className={`btn ${opsTab === 'replace' ? 'btn-primary' : 'btn-secondary'}`}
                  style={{ fontSize: '0.78rem' }}
                  onClick={() => setOpsTab('replace')}
                >
                  <RotateCcw size={14} /> Option A: Replace Cert
                </button>
                <button
                  className={`btn ${opsTab === 'crl_config' ? 'btn-primary' : 'btn-secondary'}`}
                  style={{ fontSize: '0.78rem' }}
                  onClick={() => {
                    setOpsTab('crl_config');
                    if (caStatus?.config?.parentCrlUrl) {
                      setCrlUrlInput(caStatus.config.parentCrlUrl);
                    }
                  }}
                >
                  <RefreshCw size={14} /> Parent CRL Config
                </button>
                <button
                  className={`btn ${opsTab === 'reset' ? 'btn-warning' : 'btn-secondary'}`}
                  style={{ fontSize: '0.78rem' }}
                  onClick={() => setOpsTab('reset')}
                >
                  <AlertTriangle size={14} /> Option B: Reset CA
                </button>
              </div>

              {opsTab === 'crl_config' && (
                <div>
                  <div className="alert alert-info" style={{ marginBottom: '1rem' }}>
                    <RefreshCw size={18} />
                    <div>
                      <strong>CRL Endpoints & Distribution Point (CDP) Config:</strong>
                      <p style={{ fontSize: '0.8rem', marginTop: '0.25rem' }}>
                        Configure published CRL Distribution Points embedded into issued X.509 certificates and parent sync URLs.
                      </p>
                    </div>
                  </div>

                  <form onSubmit={handleCrlUrlSubmit}>
                    {caStatus?.config?.type === 'intermediate' && (
                      <div className="form-group">
                        <label className="form-label">Parent Root CA CRL Sync Endpoint (For Sub-CA Lockout Check)</label>
                        <input
                          type="text"
                          className="form-input"
                          placeholder="http://root-ca:3001/api/crl or http://localhost:8088/api/crl"
                          value={crlUrlInput}
                          onChange={(e) => setCrlUrlInput(e.target.value)}
                        />
                      </div>
                    )}

                    <div className="form-group">
                      <label className="form-label">Published CRL Distribution Point (CDP embedded in X.509 certs)</label>
                      <input
                        type="text"
                        className="form-input"
                        placeholder="/api/crl or http://ca.enterprise.domain/api/crl"
                        value={cdpUrlInput}
                        onChange={(e) => setCdpUrlInput(e.target.value)}
                        required
                      />
                    </div>

                    <div style={{ textAlign: 'right' }}>
                      <button type="submit" className="btn btn-emerald" disabled={crlUrlLoading}>
                        {crlUrlLoading ? 'Saving Config...' : 'Save & Update CRL Configuration'}
                      </button>
                    </div>
                  </form>
                </div>
              )}

              {opsTab === 'replace' && (
                <div>
                  <div className="alert alert-info" style={{ marginBottom: '1rem' }}>
                    <CheckCircle2 size={18} />
                    <div>
                      <strong>Option A (Certificate Replacement & Renewal):</strong> Upload a new Sub-CA certificate signed by the Root CA.
                      <p style={{ fontSize: '0.8rem', marginTop: '0.25rem' }}>
                        ✅ <strong>Data Preservation:</strong> All existing certificate records, issued cert history, and audit logs are preserved in full. Restores CA status to <code>ACTIVE</code>.
                      </p>
                    </div>
                  </div>

                  {replaceError && (
                    <div className="alert alert-danger" style={{ marginBottom: '1rem' }}>
                      <div>{replaceError}</div>
                    </div>
                  )}

                  <form onSubmit={handleReplaceSubmit}>
                    <div style={{ textAlign: 'center', marginBottom: '1rem' }}>
                      <label className="btn btn-secondary" style={{ cursor: 'pointer', fontSize: '0.85rem' }}>
                        <Upload size={14} /> Upload Sub-CA PEM Bundle File
                        <input type="file" accept=".pem,.crt" style={{ display: 'none' }} onChange={handleSinglePemUpload} />
                      </label>
                    </div>

                    <div className="form-group">
                      <label className="form-label">Replacement Subordinate CA Certificate (PEM)</label>
                      <textarea
                        className="form-textarea"
                        rows={4}
                        placeholder="-----BEGIN CERTIFICATE-----\n..."
                        value={replaceCertPem}
                        onChange={(e) => setReplaceCertPem(e.target.value)}
                        required
                      />
                    </div>

                    {!caStatus?.sessionUnlocked && (
                      <div className="form-group">
                        <label className="form-label">Master Passphrase Authorization</label>
                        <input
                          type="password"
                          className="form-input"
                          placeholder="Enter Master Passphrase"
                          value={replacePassphrase}
                          onChange={(e) => setReplacePassphrase(e.target.value)}
                          required
                        />
                      </div>
                    )}

                    <div style={{ textAlign: 'right' }}>
                      <button type="submit" className="btn btn-emerald" disabled={replaceLoading}>
                        {replaceLoading ? 'Replacing Cert...' : 'Replace Sub-CA Cert & Restore Active Status'}
                      </button>
                    </div>
                  </form>
                </div>
              )}

              {opsTab === 'reset' && (
                <div>
                  <div className="alert alert-danger" style={{ marginBottom: '1rem' }}>
                    <AlertTriangle size={20} />
                    <div>
                      <strong style={{ color: '#dc2626', fontSize: '0.95rem' }}>Option B: CA Decommission & Reset Warning</strong>
                      <p style={{ fontSize: '0.825rem', marginTop: '0.35rem', lineHeight: '1.4' }}>
                        ⚠️ <strong>Implication Notice:</strong> Resetting and re-initializing the CA will remove existing certificate records from this CA instance.
                      </p>
                      <p style={{ fontSize: '0.825rem', fontWeight: 700, color: 'var(--color-emerald)', marginTop: '0.35rem' }}>
                        🔒 <strong>Audit Log Guarantee:</strong> All historical Audit Logs and compliance trails are PERMANENTLY PRESERVED for governance and security auditing.
                      </p>
                    </div>
                  </div>

                  {resetError && (
                    <div className="alert alert-danger" style={{ marginBottom: '1rem' }}>
                      <div>{resetError}</div>
                    </div>
                  )}

                  <form onSubmit={handleResetSubmit}>
                    <div className="form-group">
                      <label className="form-label">Enter Master Passphrase to Confirm CA Reset</label>
                      <input
                        type="password"
                        className="form-input"
                        placeholder="Enter Master Passphrase"
                        value={resetPassphrase}
                        onChange={(e) => setResetPassphrase(e.target.value)}
                        required
                      />
                    </div>

                    <div style={{ textAlign: 'right' }}>
                      <button type="submit" className="btn btn-danger" disabled={resetLoading}>
                        {resetLoading ? 'Resetting CA...' : 'Decommission & Reset CA Configuration'}
                      </button>
                    </div>
                  </form>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </header>
  );
}
