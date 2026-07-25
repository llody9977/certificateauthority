import React, { useState, useEffect } from 'react';
import { ShieldCheck, Check, Save, Play, AlertCircle, FileCode, Sliders, Lock, RefreshCw, Key } from 'lucide-react';

export function OpaManager() {
  const [policies, setPolicies] = useState([]);
  const [activePolicy, setActivePolicy] = useState(null);

  // Form State
  const [allowedAlgorithms, setAllowedAlgorithms] = useState(['ECDSA_P256', 'ECDSA_P384', 'RSA_2048', 'RSA_4096', 'ED25519']);
  const [allowedCertTypes, setAllowedCertTypes] = useState(['web_server', 'client_auth', 'mtls', 'code_signing', 'smime', 'ocsp_signer', 'sub_ca', 'acme_tls', 'ssh_user', 'ssh_host']);
  const [maxDaysByProfile, setMaxDaysByProfile] = useState({
    short_lived: 7,
    acme_tls: 90,
    standard: 365,
    infrastructure: 730,
    code_signing: 365,
    ocsp_signer: 180,
    ssh_user: 30,
    ssh_host: 365
  });
  const [allowWildcards, setAllowWildcards] = useState(false);
  const [requireSan, setRequireSan] = useState(true);

  const [activeTab, setActiveTab] = useState('form'); // 'form' | 'rego' | 'tester'
  const [loading, setLoading] = useState(false);
  const [saveSuccess, setSaveSuccess] = useState(false);

  // Simulator state
  const [testAlgorithm, setTestAlgorithm] = useState('ECDSA_P256');
  const [testCertType, setTestCertType] = useState('web_server');
  const [testProfile, setTestProfile] = useState('standard');
  const [testValidityDays, setTestValidityDays] = useState(365);
  const [testSans, setTestSans] = useState('app.domain.com');
  const [testResult, setTestResult] = useState(null);

  const fetchPolicies = async () => {
    try {
      const res = await fetch('/api/policies');
      const data = await res.json();
      if (res.ok && data.policies && data.policies.length > 0) {
        setPolicies(data.policies);
        const p = data.policies[0];
        setActivePolicy(p);
        if (p.settings) {
          if (p.settings.allowedAlgorithms) setAllowedAlgorithms(p.settings.allowedAlgorithms);
          if (p.settings.allowedCertTypes) setAllowedCertTypes(p.settings.allowedCertTypes);
          if (p.settings.maxDaysByProfile) setMaxDaysByProfile(p.settings.maxDaysByProfile);
          if (p.settings.allowWildcards !== undefined) setAllowWildcards(p.settings.allowWildcards);
          if (p.settings.requireSan !== undefined) setRequireSan(p.settings.requireSan);
        }
      }
    } catch (err) {
      console.error('Error fetching policies:', err);
    }
  };

  useEffect(() => {
    fetchPolicies();
  }, []);

  const toggleAlg = (alg) => {
    if (allowedAlgorithms.includes(alg)) {
      setAllowedAlgorithms(allowedAlgorithms.filter(a => a !== alg));
    } else {
      setAllowedAlgorithms([...allowedAlgorithms, alg]);
    }
  };

  const toggleCertType = (type) => {
    if (allowedCertTypes.includes(type)) {
      setAllowedCertTypes(allowedCertTypes.filter(t => t !== type));
    } else {
      setAllowedCertTypes([...allowedCertTypes, type]);
    }
  };

  const handleDaysChange = (profile, days) => {
    setMaxDaysByProfile({
      ...maxDaysByProfile,
      [profile]: parseInt(days) || 0
    });
  };

  const handleSaveForm = async () => {
    if (!activePolicy) return;
    setLoading(true);
    setSaveSuccess(false);

    const newSettings = {
      allowedAlgorithms,
      allowedCertTypes,
      maxDaysByProfile,
      allowWildcards,
      requireSan
    };

    try {
      const res = await fetch(`/api/policies/${activePolicy.id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ settings: newSettings, enabled: true })
      });

      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Failed to save policy form');

      setSaveSuccess(true);
      setTimeout(() => setSaveSuccess(false), 3000);
      fetchPolicies();
    } catch (err) {
      alert(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleTestPolicy = () => {
    const sansArray = testSans.split(',').map(s => s.trim()).filter(Boolean);
    const violations = [];

    if (!allowedAlgorithms.includes(testAlgorithm)) {
      violations.push(`Algorithm '${testAlgorithm}' is forbidden by OPA policy form settings.`);
    }

    if (!allowedCertTypes.includes(testCertType)) {
      violations.push(`Certificate type '${testCertType}' is forbidden by OPA policy form settings.`);
    }

    const maxDays = maxDaysByProfile[testProfile];
    if (!maxDays) {
      violations.push(`Profile '${testProfile}' is not configured in policy limits.`);
    } else if (testValidityDays > maxDays) {
      violations.push(`Requested validity (${testValidityDays} days) exceeds configured limit (${maxDays} days) for profile '${testProfile}'.`);
    }

    if (requireSan && sansArray.length === 0) {
      violations.push(`Subject Alternative Name (SAN) is required by OPA policy.`);
    }

    if (!allowWildcards && testProfile !== 'infrastructure' && sansArray.some(s => s.startsWith('*.'))) {
      violations.push(`Wildcard SANs strictly restricted unless using 'infrastructure' profile.`);
    }

    if (violations.length > 0) {
      setTestResult({ allowed: false, violations });
    } else {
      setTestResult({ allowed: true, reason: 'Complies with OPA Form Policy Configuration' });
    }
  };

  const allAlgorithmsList = ['ECDSA_P256', 'ECDSA_P384', 'RSA_2048', 'RSA_4096', 'ED25519'];
  const allCertTypesList = [
    { id: 'web_server', label: 'Web Server (TLS)' },
    { id: 'client_auth', label: 'Client Auth' },
    { id: 'mtls', label: 'mTLS Mutual' },
    { id: 'code_signing', label: 'Code Signing' },
    { id: 'smime', label: 'S/MIME Email' },
    { id: 'ocsp_signer', label: 'OCSP Signer' },
    { id: 'sub_ca', label: 'Subordinate CA' },
    { id: 'acme_tls', label: 'ACME Protocol Automated TLS' },
    { id: 'ssh_user', label: 'SSH User Certificate' },
    { id: 'ssh_host', label: 'SSH Host Certificate' }
  ];

  return (
    <div>
      <div className="panel">
        <div className="panel-header">
          <div>
            <h2 className="panel-title">
              <Sliders style={{ color: 'var(--color-blue)' }} size={22} />
              OPA Form-Based Governance & Compliance Builder
            </h2>
            <p className="panel-description">
              Configure OPA compliance rules via structured UI controls. Automatically generates error-free Rego policy rules behind the scenes.
            </p>
          </div>

          <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
            {saveSuccess && (
              <span className="badge badge-emerald">
                <Check size={12} /> Form Policy Saved & Rego Compiled
              </span>
            )}
            <button className="btn btn-emerald" onClick={handleSaveForm} disabled={loading}>
              <Save size={14} /> {loading ? 'Saving...' : 'Save & Enforce OPA Policy'}
            </button>
          </div>
        </div>

        {/* View Mode Tabs */}
        <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '1.25rem' }}>
          <button
            className={`btn ${activeTab === 'form' ? 'btn-primary' : 'btn-secondary'}`}
            onClick={() => setActiveTab('form')}
          >
            <Sliders size={15} /> Form Policy Settings
          </button>
          <button
            className={`btn ${activeTab === 'rego' ? 'btn-primary' : 'btn-secondary'}`}
            onClick={() => setActiveTab('rego')}
          >
            <FileCode size={15} /> Generated Rego Preview
          </button>
          <button
            className={`btn ${activeTab === 'tester' ? 'btn-primary' : 'btn-secondary'}`}
            onClick={() => setActiveTab('tester')}
          >
            <Play size={15} /> Policy Simulator
          </button>
        </div>

        {/* TAB 1: UI FORM BUILDER */}
        {activeTab === 'form' && (
          <div>
            {/* Section 1: Approved Signature Algorithms */}
            <div style={{ background: '#ffffff', padding: '1.25rem', borderRadius: '8px', border: '1px solid var(--border-subtle)', marginBottom: '1.25rem' }}>
              <h4 style={{ fontFamily: 'var(--font-heading)', marginBottom: '0.5rem', fontSize: '1.05rem', color: 'var(--text-heading)' }}>
                1. Approved Signature Algorithms
              </h4>
              <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '1rem' }}>
                Select signature algorithms allowed for X.509, ACME, and SSH credential signing.
              </p>

              <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
                {allAlgorithmsList.map((alg) => (
                  <label
                    key={alg}
                    style={{
                      padding: '0.66rem 1rem',
                      borderRadius: '6px',
                      border: allowedAlgorithms.includes(alg) ? '2px solid var(--color-blue)' : '1px solid var(--border-accent)',
                      background: allowedAlgorithms.includes(alg) ? '#eff6ff' : '#ffffff',
                      cursor: 'pointer',
                      fontSize: '0.85rem',
                      fontFamily: 'var(--font-mono)',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '0.5rem'
                    }}
                  >
                    <input
                      type="checkbox"
                      checked={allowedAlgorithms.includes(alg)}
                      onChange={() => toggleAlg(alg)}
                    />
                    {alg}
                  </label>
                ))}
              </div>
            </div>

            {/* Section 2: Approved Credential & Certificate Types */}
            <div style={{ background: '#ffffff', padding: '1.25rem', borderRadius: '8px', border: '1px solid var(--border-subtle)', marginBottom: '1.25rem' }}>
              <h4 style={{ fontFamily: 'var(--font-heading)', marginBottom: '0.5rem', fontSize: '1.05rem', color: 'var(--text-heading)' }}>
                2. Approved Certificate & Credential Types (X.509, ACME, OpenSSH)
              </h4>
              <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '1rem' }}>
                Toggle which certificate and protocol types users and automated pipelines are permitted to request.
              </p>

              <div className="grid-3">
                {allCertTypesList.map((item) => (
                  <label
                    key={item.id}
                    style={{
                      padding: '0.75rem 1rem',
                      borderRadius: '6px',
                      border: allowedCertTypes.includes(item.id) ? '2px solid var(--color-indigo)' : '1px solid var(--border-accent)',
                      background: allowedCertTypes.includes(item.id) ? '#eef2ff' : '#ffffff',
                      cursor: 'pointer',
                      fontSize: '0.875rem',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '0.5rem'
                    }}
                  >
                    <input
                      type="checkbox"
                      checked={allowedCertTypes.includes(item.id)}
                      onChange={() => toggleCertType(item.id)}
                    />
                    <strong style={{ color: 'var(--text-heading)' }}>{item.label}</strong>
                  </label>
                ))}
              </div>
            </div>

            {/* Section 3: Maximum Validity Boundaries per Profile */}
            <div style={{ background: '#ffffff', padding: '1.25rem', borderRadius: '8px', border: '1px solid var(--border-subtle)', marginBottom: '1.25rem' }}>
              <h4 style={{ fontFamily: 'var(--font-heading)', marginBottom: '0.5rem', fontSize: '1.05rem', color: 'var(--text-heading)' }}>
                3. Profile Expiration Boundaries (Maximum Allowed Validity in Days)
              </h4>
              <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '1rem' }}>
                Specify maximum validity period limits for each profile. Custom validity inputs outside profile limits will be denied by OPA.
              </p>

              <div className="grid-4">
                <div className="form-group">
                  <label className="form-label">short_lived (Days)</label>
                  <input
                    type="number"
                    className="form-input"
                    value={maxDaysByProfile.short_lived || 7}
                    onChange={(e) => handleDaysChange('short_lived', e.target.value)}
                  />
                </div>

                <div className="form-group">
                  <label className="form-label">acme_tls (Days)</label>
                  <input
                    type="number"
                    className="form-input"
                    value={maxDaysByProfile.acme_tls || 90}
                    onChange={(e) => handleDaysChange('acme_tls', e.target.value)}
                  />
                </div>

                <div className="form-group">
                  <label className="form-label">standard (Days)</label>
                  <input
                    type="number"
                    className="form-input"
                    value={maxDaysByProfile.standard || 365}
                    onChange={(e) => handleDaysChange('standard', e.target.value)}
                  />
                </div>

                <div className="form-group">
                  <label className="form-label">infrastructure (Days)</label>
                  <input
                    type="number"
                    className="form-input"
                    value={maxDaysByProfile.infrastructure || 730}
                    onChange={(e) => handleDaysChange('infrastructure', e.target.value)}
                  />
                </div>

                <div className="form-group">
                  <label className="form-label">code_signing (Days)</label>
                  <input
                    type="number"
                    className="form-input"
                    value={maxDaysByProfile.code_signing || 365}
                    onChange={(e) => handleDaysChange('code_signing', e.target.value)}
                  />
                </div>

                <div className="form-group">
                  <label className="form-label">ssh_user (Days)</label>
                  <input
                    type="number"
                    className="form-input"
                    value={maxDaysByProfile.ssh_user || 30}
                    onChange={(e) => handleDaysChange('ssh_user', e.target.value)}
                  />
                </div>

                <div className="form-group">
                  <label className="form-label">ssh_host (Days)</label>
                  <input
                    type="number"
                    className="form-input"
                    value={maxDaysByProfile.ssh_host || 365}
                    onChange={(e) => handleDaysChange('ssh_host', e.target.value)}
                  />
                </div>
              </div>
            </div>

            {/* Section 4: SAN & Wildcard Security Controls */}
            <div style={{ background: '#ffffff', padding: '1.25rem', borderRadius: '8px', border: '1px solid var(--border-subtle)' }}>
              <h4 style={{ fontFamily: 'var(--font-heading)', marginBottom: '0.5rem', fontSize: '1.05rem', color: 'var(--text-heading)' }}>
                4. SAN & Security Constraints
              </h4>

              <div className="grid-2">
                <label style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', padding: '0.75rem', border: '1px solid var(--border-accent)', borderRadius: '6px', cursor: 'pointer' }}>
                  <input
                    type="checkbox"
                    checked={requireSan}
                    onChange={(e) => setRequireSan(e.target.checked)}
                  />
                  <div>
                    <strong style={{ display: 'block', fontSize: '0.875rem' }}>Require Subject Alternative Name (SAN)</strong>
                    <small style={{ color: 'var(--text-muted)' }}>Mandates at least one SAN entry per certificate request.</small>
                  </div>
                </label>

                <label style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', padding: '0.75rem', border: '1px solid var(--border-accent)', borderRadius: '6px', cursor: 'pointer' }}>
                  <input
                    type="checkbox"
                    checked={allowWildcards}
                    onChange={(e) => setAllowWildcards(e.target.checked)}
                  />
                  <div>
                    <strong style={{ display: 'block', fontSize: '0.875rem' }}>Globally Allow Wildcard SANs (*.domain.com)</strong>
                    <small style={{ color: 'var(--text-muted)' }}>If unchecked, wildcards are strictly limited to 'infrastructure' profile.</small>
                  </div>
                </label>
              </div>
            </div>
          </div>
        )}

        {/* TAB 2: COMPILED REGO PREVIEW */}
        {activeTab === 'rego' && (
          <div>
            <div style={{ marginBottom: '0.5rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <label className="form-label">Automatically Compiled Rego Policy Code (Read-Only)</label>
              <span className="badge badge-indigo">Auto-Generated from UI Form</span>
            </div>
            <textarea
              className="form-textarea"
              rows={18}
              style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', background: '#0b0f19', color: '#38bdf8' }}
              value={activePolicy?.rego || '// Rego will compile upon saving policy form...'}
              readOnly
            />
          </div>
        )}

        {/* TAB 3: SIMULATOR */}
        {activeTab === 'tester' && (
          <div>
            <label className="form-label" style={{ marginBottom: '0.75rem', display: 'block' }}>
              OPA Form Policy Live Evaluator
            </label>
            <div style={{ background: '#ffffff', padding: '1.25rem', borderRadius: '8px', border: '1px solid var(--border-accent)' }}>
              <div className="grid-3">
                <div className="form-group">
                  <label className="form-label">Algorithm</label>
                  <select className="form-select" value={testAlgorithm} onChange={(e) => setTestAlgorithm(e.target.value)}>
                    {allAlgorithmsList.map(a => (
                      <option key={a} value={a}>{a}</option>
                    ))}
                  </select>
                </div>

                <div className="form-group">
                  <label className="form-label">Cert Type</label>
                  <select className="form-select" value={testCertType} onChange={(e) => setTestCertType(e.target.value)}>
                    {allCertTypesList.map(t => (
                      <option key={t.id} value={t.id}>{t.label}</option>
                    ))}
                  </select>
                </div>

                <div className="form-group">
                  <label className="form-label">Profile</label>
                  <select className="form-select" value={testProfile} onChange={(e) => setTestProfile(e.target.value)}>
                    <option value="short_lived">short_lived</option>
                    <option value="acme_tls">acme_tls</option>
                    <option value="standard">standard</option>
                    <option value="infrastructure">infrastructure</option>
                    <option value="code_signing">code_signing</option>
                    <option value="ssh_user">ssh_user</option>
                    <option value="ssh_host">ssh_host</option>
                  </select>
                </div>
              </div>

              <div className="grid-2">
                <div className="form-group">
                  <label className="form-label">Requested Validity (Days)</label>
                  <input
                    type="number"
                    className="form-input"
                    value={testValidityDays}
                    onChange={(e) => setTestValidityDays(parseInt(e.target.value))}
                  />
                </div>

                <div className="form-group">
                  <label className="form-label">SANs / Principals</label>
                  <input className="form-input" value={testSans} onChange={(e) => setTestSans(e.target.value)} />
                </div>
              </div>

              <button className="btn btn-primary" style={{ width: '100%' }} onClick={handleTestPolicy}>
                <Play size={14} /> Evaluate Form Policy Simulation
              </button>

              {testResult && (
                <div style={{ marginTop: '1rem' }}>
                  {testResult.allowed ? (
                    <div className="alert alert-success">
                      <Check size={18} />
                      <div>
                        <strong>ALLOWED:</strong> {testResult.reason}
                      </div>
                    </div>
                  ) : (
                    <div className="alert alert-danger">
                      <AlertCircle size={18} />
                      <div>
                        <strong>DENIED BY OPA FORM POLICY:</strong>
                        <ul style={{ paddingLeft: '1.2rem', marginTop: '0.25rem' }}>
                          {testResult.violations.map((v, i) => (
                            <li key={i}>{v}</li>
                          ))}
                        </ul>
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
