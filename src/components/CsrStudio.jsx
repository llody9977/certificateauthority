import React, { useState } from 'react';
import { ShieldCheck, FileText, Key, Check, AlertCircle, Terminal, Lock, Unlock, ArrowRight, Server } from 'lucide-react';

export function CsrStudio({ caStatus, onCertIssued }) {
  const [activeSubTab, setActiveSubTab] = useState('issue');

  // CSR Generation Form state
  const [csrCn, setCsrCn] = useState('app.internal.domain.com');
  const [csrOrg, setCsrOrg] = useState('Enterprise Corp');
  const [csrOu, setCsrOu] = useState('DevOps Engineering');
  const [csrCountry, setCsrCountry] = useState('US');
  const [csrState, setCsrState] = useState('California');
  const [csrLocality, setCsrLocality] = useState('San Francisco');
  const [csrSans, setCsrSans] = useState('app.internal.domain.com, 10.0.4.15');
  const [csrAlg, setCsrAlg] = useState('RSA_2048');

  const [generatedCsrResult, setGeneratedCsrResult] = useState(null);
  const [csrLoading, setCsrLoading] = useState(false);

  // Certificate Issuance Form state
  const [issueCn, setIssueCn] = useState('api.service.internal');
  const [issueOrg, setIssueOrg] = useState('Enterprise Corp');
  const [issueOu, setIssueOu] = useState('Infrastructure');
  const [issueCountry, setIssueCountry] = useState('US');
  const [issueState, setIssueState] = useState('California');
  const [issueLocality, setIssueLocality] = useState('San Francisco');
  const [issueEmail, setIssueEmail] = useState('admin@enterprise.com');
  const [issueSans, setIssueSans] = useState('api.service.internal, api-lb.service.internal');
  const [certType, setCertType] = useState('web_server');
  const [profile, setProfile] = useState('standard');
  const [validityDays, setValidityDays] = useState(365);
  const [algorithm, setAlgorithm] = useState('RSA_2048');
  const [pastedCsrPem, setPastedCsrPem] = useState('');
  const [masterPassphrase, setMasterPassphrase] = useState('');

  const [issueLoading, setIssueLoading] = useState(false);
  const [issueError, setIssueError] = useState(null);
  const [opaViolation, setOpaViolation] = useState(null);

  // OpenSSH Certificate Form state
  const [sshIdentity, setSshIdentity] = useState('developer@enterprise.com');
  const [sshCertType, setSshCertType] = useState('ssh_user');
  const [sshPrincipals, setSshPrincipals] = useState('ubuntu, devops, root');
  const [sshValidityDays, setSshValidityDays] = useState(30);
  const [sshAlg, setSshAlg] = useState('ECDSA_P256');
  const [sshPassphrase, setSshPassphrase] = useState('');
  const [sshIssuedResult, setSshIssuedResult] = useState(null);
  const [sshLoading, setSshLoading] = useState(false);
  const [sshError, setSshError] = useState(null);

  const handleProfileChange = (selectedProfile) => {
    setProfile(selectedProfile);
    if (selectedProfile === 'short_lived') setValidityDays(7);
    else if (selectedProfile === 'acme_tls') setValidityDays(90);
    else if (selectedProfile === 'standard') setValidityDays(365);
    else if (selectedProfile === 'infrastructure') setValidityDays(730);
    else if (selectedProfile === 'code_signing') setValidityDays(365);
  };

  const handleGenerateCsr = async () => {
    setCsrLoading(true);
    try {
      const sansArray = csrSans.split(',').map(s => s.trim()).filter(Boolean);
      const res = await fetch('/api/csr/create', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          commonName: csrCn,
          organization: csrOrg,
          organizationalUnit: csrOu,
          country: csrCountry,
          state: csrState,
          locality: csrLocality,
          sans: sansArray,
          algorithm: csrAlg
        })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Failed to generate CSR');
      setGeneratedCsrResult(data.csr);
    } catch (err) {
      alert(err.message);
    } finally {
      setCsrLoading(false);
    }
  };

  const handleIssueSubmit = async (e) => {
    e.preventDefault();
    setIssueLoading(true);
    setIssueError(null);
    setOpaViolation(null);

    try {
      const sansArray = issueSans.split(',').map(s => s.trim()).filter(Boolean);

      const res = await fetch('/api/certificates/issue', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          commonName: issueCn,
          organization: issueOrg,
          organizationalUnit: issueOu,
          country: issueCountry,
          state: issueState,
          locality: issueLocality,
          emailAddress: issueEmail,
          certType,
          profile,
          validityDays: parseInt(validityDays),
          algorithm,
          sans: sansArray,
          csrPem: pastedCsrPem || null,
          masterPassphrase: masterPassphrase || null
        })
      });

      const data = await res.json();
      if (!res.ok) {
        if (data.error && data.error.includes('OPA Policy Denied')) {
          setOpaViolation(data.error);
        } else {
          throw new Error(data.error || 'Failed to issue certificate');
        }
        return;
      }

      alert(`Certificate issued successfully! Serial Number: ${data.certificate.serialNumber}`);
      if (onCertIssued) onCertIssued();
    } catch (err) {
      setIssueError(err.message);
    } finally {
      setIssueLoading(false);
    }
  };

  const handleSshIssueSubmit = async (e) => {
    e.preventDefault();
    setSshLoading(true);
    setSshError(null);

    try {
      const principalsArray = sshPrincipals.split(',').map(p => p.trim()).filter(Boolean);
      const res = await fetch('/api/ssh/issue', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          identity: sshIdentity,
          certType: sshCertType,
          principals: principalsArray,
          validityDays: parseInt(sshValidityDays),
          algorithm: sshAlg,
          masterPassphrase: sshPassphrase || null
        })
      });

      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Failed to issue OpenSSH Certificate');

      setSshIssuedResult(data.sshCertificate);
    } catch (err) {
      setSshError(err.message);
    } finally {
      setSshLoading(false);
    }
  };

  return (
    <div>
      <div style={{ display: 'flex', gap: '0.75rem', marginBottom: '1.25rem' }}>
        <button
          className={`btn ${activeSubTab === 'issue' ? 'btn-primary' : 'btn-secondary'}`}
          onClick={() => setActiveSubTab('issue')}
        >
          <ShieldCheck size={16} /> X.509 & ACME TLS Request
        </button>
        <button
          className={`btn ${activeSubTab === 'ssh' ? 'btn-primary' : 'btn-secondary'}`}
          onClick={() => setActiveSubTab('ssh')}
        >
          <Terminal size={16} /> OpenSSH User & Host Certificates
        </button>
        <button
          className={`btn ${activeSubTab === 'generate_csr' ? 'btn-primary' : 'btn-secondary'}`}
          onClick={() => setActiveSubTab('generate_csr')}
        >
          <FileText size={16} /> Standalone CSR Studio
        </button>
      </div>

      {activeSubTab === 'issue' && (
        <div className="panel">
          <div className="panel-header">
            <div>
              <h3 className="panel-title">
                <ShieldCheck style={{ color: 'var(--color-blue)' }} size={20} />
                Issue X.509 / ACME TLS Certificate (OPA Policy Governed)
              </h3>
              <p className="panel-description">
                Request certificate signing. Parameters are validated against OPA Form Policy rules before issuance.
              </p>
            </div>
          </div>

          {issueError && (
            <div className="alert alert-danger">
              <AlertCircle size={18} />
              <div>{issueError}</div>
            </div>
          )}

          {opaViolation && (
            <div className="alert alert-warning">
              <ShieldCheck size={20} style={{ color: 'var(--color-amber)' }} />
              <div>
                <strong style={{ color: 'var(--color-amber)', display: 'block' }}>OPA Policy Compliance Violation</strong>
                <p style={{ fontSize: '0.85rem' }}>{opaViolation}</p>
              </div>
            </div>
          )}

          <form onSubmit={handleIssueSubmit}>
            <div className="grid-3" style={{ marginBottom: '1.25rem' }}>
              <div className="form-group">
                <label className="form-label">Certificate / Protocol Type</label>
                <select className="form-select" value={certType} onChange={(e) => setCertType(e.target.value)}>
                  <option value="web_server">Web Server (TLS Server)</option>
                  <option value="acme_tls">ACME Protocol Automated TLS</option>
                  <option value="client_auth">Client Auth (TLS Client)</option>
                  <option value="mtls">mTLS Mutual (Server + Client)</option>
                  <option value="code_signing">Code Signing</option>
                  <option value="smime">S/MIME Email Protection</option>
                  <option value="ocsp_signer">OCSP Responder Signer</option>
                  <option value="sub_ca">Subordinate Intermediate CA</option>
                </select>
              </div>

              <div className="form-group">
                <label className="form-label">Expiration Profile (OPA Enforced)</label>
                <select className="form-select" value={profile} onChange={(e) => handleProfileChange(e.target.value)}>
                  <option value="short_lived">Short-Lived Ephemeral (7 Days)</option>
                  <option value="acme_tls">ACME Automated Profile (90 Days)</option>
                  <option value="standard">Standard Enterprise (365 Days / 1 Year)</option>
                  <option value="infrastructure">Infrastructure Core (730 Days / 2 Years)</option>
                  <option value="code_signing">Code Signing Profile (365 Days)</option>
                </select>
              </div>

              <div className="form-group">
                <label className="form-label">Key Algorithm</label>
                <select className="form-select" value={algorithm} onChange={(e) => setAlgorithm(e.target.value)}>
                  <option value="RSA_2048">RSA 2048-bit</option>
                  <option value="RSA_4096">RSA 4096-bit</option>
                  <option value="ECDSA_P256">ECDSA P-256 (ECC)</option>
                  <option value="ECDSA_P384">ECDSA P-384 (ECC)</option>
                  <option value="ED25519">Ed25519</option>
                </select>
              </div>
            </div>

            <div className="form-group">
              <label className="form-label">Common Name (CN / Primary Domain)</label>
              <input
                type="text"
                className="form-input"
                value={issueCn}
                onChange={(e) => setIssueCn(e.target.value)}
                placeholder="e.g. vault.internal.domain.com"
                required
              />
            </div>

            <div className="form-group">
              <label className="form-label">Subject Alternative Names (SANs) — Comma Separated</label>
              <input
                type="text"
                className="form-input"
                value={issueSans}
                onChange={(e) => setIssueSans(e.target.value)}
                placeholder="e.g. vault.internal, 10.0.1.5, api.domain.com"
              />
            </div>

            <div className="grid-2">
              <div className="form-group">
                <label className="form-label">Organization (O)</label>
                <input className="form-input" value={issueOrg} onChange={(e) => setIssueOrg(e.target.value)} />
              </div>
              <div className="form-group">
                <label className="form-label">Organizational Unit (OU)</label>
                <input className="form-input" value={issueOu} onChange={(e) => setIssueOu(e.target.value)} />
              </div>
            </div>

            <div style={{ background: caStatus?.sessionUnlocked ? '#ecfdf5' : '#f8fafc', padding: '1.25rem', borderRadius: '8px', border: caStatus?.sessionUnlocked ? '1px solid #a7f3d0' : '1px solid var(--border-subtle)', margin: '1.25rem 0' }}>
              {caStatus?.sessionUnlocked ? (
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: '#047857' }}>
                  <Unlock size={18} />
                  <div>
                    <strong>Authorized via Unlocked CA Session</strong>
                    <p style={{ fontSize: '0.8rem' }}>Master passphrase entry is not required during active unlocked session.</p>
                  </div>
                </div>
              ) : (
                <div className="form-group" style={{ marginBottom: 0 }}>
                  <label className="form-label">Master Passphrase (Required unless CA Session Unlocked)</label>
                  <input
                    type="password"
                    className="form-input"
                    placeholder="Enter Master Passphrase"
                    value={masterPassphrase}
                    onChange={(e) => setMasterPassphrase(e.target.value)}
                    required={!caStatus?.sessionUnlocked}
                  />
                </div>
              )}
            </div>

            <button type="submit" className="btn btn-emerald" disabled={issueLoading}>
              {issueLoading ? 'Evaluating OPA & Signing...' : 'Evaluate OPA Policy & Sign Certificate'}
            </button>
          </form>
        </div>
      )}

      {activeSubTab === 'ssh' && (
        <div className="panel">
          <div className="panel-header">
            <div>
              <h3 className="panel-title">
                <Terminal style={{ color: 'var(--color-indigo)' }} size={20} />
                OpenSSH Certificate Signing Authority
              </h3>
              <p className="panel-description">
                Issue short-lived OpenSSH User and Host certificates replacing permanent SSH public keys.
              </p>
            </div>
          </div>

          {sshError && (
            <div className="alert alert-danger">
              <AlertCircle size={18} />
              <div>{sshError}</div>
            </div>
          )}

          <div className="grid-2">
            <form onSubmit={handleSshIssueSubmit}>
              <div className="form-group">
                <label className="form-label">SSH Credential Type</label>
                <select className="form-select" value={sshCertType} onChange={(e) => setSshCertType(e.target.value)}>
                  <option value="ssh_user">OpenSSH User Certificate (ssh_user)</option>
                  <option value="ssh_host">OpenSSH Host Certificate (ssh_host)</option>
                </select>
              </div>

              <div className="form-group">
                <label className="form-label">Key Identity (Username / Host Name)</label>
                <input
                  type="text"
                  className="form-input"
                  value={sshIdentity}
                  onChange={(e) => setSshIdentity(e.target.value)}
                  placeholder="e.g. developer@corp.com or server.internal"
                  required
                />
              </div>

              <div className="form-group">
                <label className="form-label">Allowed Principals (Comma Separated)</label>
                <input
                  type="text"
                  className="form-input"
                  value={sshPrincipals}
                  onChange={(e) => setSshPrincipals(e.target.value)}
                  placeholder="e.g. ubuntu, root, devops"
                  required
                />
              </div>

              <div className="grid-2">
                <div className="form-group">
                  <label className="form-label">Validity (Days)</label>
                  <input
                    type="number"
                    className="form-input"
                    value={sshValidityDays}
                    onChange={(e) => setSshValidityDays(e.target.value)}
                  />
                </div>
                <div className="form-group">
                  <label className="form-label">Algorithm</label>
                  <select className="form-select" value={sshAlg} onChange={(e) => setSshAlg(e.target.value)}>
                    <option value="ECDSA_P256">ECDSA P-256 (NIST)</option>
                    <option value="ED25519">Ed25519</option>
                    <option value="RSA_2048">RSA 2048</option>
                  </select>
                </div>
              </div>

              {!caStatus?.sessionUnlocked && (
                <div className="form-group">
                  <label className="form-label">Master Passphrase Authorization</label>
                  <input
                    type="password"
                    className="form-input"
                    value={sshPassphrase}
                    onChange={(e) => setSshPassphrase(e.target.value)}
                    placeholder="Enter Master Passphrase"
                    required
                  />
                </div>
              )}

              <button type="submit" className="btn btn-primary" disabled={sshLoading}>
                {sshLoading ? 'Signing SSH Certificate...' : 'Sign OpenSSH Certificate'}
              </button>
            </form>

            <div>
              {sshIssuedResult ? (
                <div style={{ background: '#f8fafc', padding: '1.25rem', borderRadius: '8px', border: '1px solid var(--border-accent)' }}>
                  <div style={{ display: 'flex', gap: '0.4rem', alignItems: 'center', marginBottom: '0.75rem' }}>
                    <Check size={18} style={{ color: 'var(--color-emerald)' }} />
                    <strong style={{ fontSize: '0.95rem' }}>OpenSSH Certificate Issued Successfully</strong>
                  </div>

                  <div className="form-group">
                    <small className="form-label">Key ID</small>
                    <span className="code-inline">{sshIssuedResult.identity}</span>
                  </div>

                  <div className="form-group">
                    <small className="form-label">Valid Principals</small>
                    <div style={{ display: 'flex', gap: '0.35rem' }}>
                      {sshIssuedResult.principals.map((p, i) => (
                        <span key={i} className="badge badge-indigo">{p}</span>
                      ))}
                    </div>
                  </div>

                  <div className="form-group">
                    <small className="form-label">Issued OpenSSH Certificate Payload</small>
                    <textarea
                      className="form-textarea"
                      rows={6}
                      value={JSON.stringify(sshIssuedResult.sshCertPayload, null, 2)}
                      readOnly
                      style={{ background: '#0b0f19', color: '#38bdf8' }}
                    />
                  </div>
                </div>
              ) : (
                <div style={{ background: '#f8fafc', padding: '2rem', borderRadius: '8px', border: '1px dashed var(--border-accent)', textAlign: 'center', height: '100%', display: 'flex', flexDirection: 'column', justifyContent: 'center', alignItems: 'center' }}>
                  <Terminal size={32} style={{ color: 'var(--text-dim)', marginBottom: '0.75rem' }} />
                  <p style={{ fontSize: '0.875rem', color: 'var(--text-muted)' }}>
                    Fill in SSH identity and click "Sign OpenSSH Certificate" to produce signed credential payload.
                  </p>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {activeSubTab === 'generate_csr' && (
        <div className="panel">
          <div className="panel-header">
            <div>
              <h3 className="panel-title">
                <FileText style={{ color: 'var(--color-indigo)' }} size={20} />
                Standalone CSR Studio
              </h3>
              <p className="panel-description">
                Generate private key pairs and PKCS#10 Certificate Signing Requests locally.
              </p>
            </div>
          </div>

          <div className="grid-2">
            <div>
              <div className="form-group">
                <label className="form-label">Common Name (CN)</label>
                <input className="form-input" value={csrCn} onChange={(e) => setCsrCn(e.target.value)} />
              </div>

              <div className="form-group">
                <label className="form-label">SANs (Comma Separated)</label>
                <input className="form-input" value={csrSans} onChange={(e) => setCsrSans(e.target.value)} />
              </div>

              <div className="form-group">
                <label className="form-label">Algorithm</label>
                <select className="form-select" value={csrAlg} onChange={(e) => setCsrAlg(e.target.value)}>
                  <option value="RSA_2048">RSA 2048-bit</option>
                  <option value="RSA_4096">RSA 4096-bit</option>
                </select>
              </div>

              <button className="btn btn-primary" onClick={handleGenerateCsr} disabled={csrLoading}>
                {csrLoading ? 'Generating CSR...' : 'Generate CSR & Private Key'}
              </button>
            </div>

            <div>
              {generatedCsrResult ? (
                <div>
                  <div className="form-group">
                    <label className="form-label">Generated CSR (PEM)</label>
                    <textarea className="form-textarea" rows={6} value={generatedCsrResult.csrPem} readOnly />
                  </div>

                  <div className="form-group">
                    <label className="form-label">Private Key (PEM)</label>
                    <textarea className="form-textarea" rows={6} value={generatedCsrResult.privateKeyPem} readOnly />
                  </div>
                </div>
              ) : (
                <div style={{ background: '#f8fafc', padding: '2rem', borderRadius: '8px', border: '1px dashed var(--border-accent)', textAlign: 'center', height: '100%', display: 'flex', flexDirection: 'column', justifyContent: 'center', alignItems: 'center' }}>
                  <FileText size={32} style={{ color: 'var(--text-dim)', marginBottom: '0.75rem' }} />
                  <p style={{ fontSize: '0.875rem', color: 'var(--text-muted)' }}>
                    Fill in details and click "Generate CSR" to produce PKCS#10 request.
                  </p>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
