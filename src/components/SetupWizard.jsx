import React, { useState } from 'react';
import { Shield, Key, FileCheck, Lock, ArrowRight, Check, AlertCircle, Server, Upload, Download, FileText } from 'lucide-react';

export function SetupWizard({ onComplete, onClose }) {
  const [step, setStep] = useState(1);
  const [caType, setCaType] = useState('root');
  
  // Form fields
  const [caName, setCaName] = useState('Enterprise Trust Root CA v1');
  const [organization, setOrganization] = useState('Enterprise PKI Corp');
  const [ou, setOu] = useState('Security & Identity Infrastructure');
  const [country, setCountry] = useState('US');
  const [state, setState] = useState('California');
  const [locality, setLocality] = useState('San Francisco');
  const [algorithm, setAlgorithm] = useState('RSA_2048');
  const [validityYears, setValidityYears] = useState(10);
  const [passphrase, setPassphrase] = useState('');
  const [confirmPassphrase, setConfirmPassphrase] = useState('');

  // Intermediate state
  const [subCaCsrPem, setSubCaCsrPem] = useState('');
  const [subCaPrivateKeyPem, setSubCaPrivateKeyPem] = useState('');
  const [parentRootPem, setParentRootPem] = useState('');
  const [signedSubCaCertPem, setSignedSubCaCertPem] = useState('');
  const [parentCrlUrl, setParentCrlUrl] = useState('http://localhost:8088/api/crl');

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  // Single PEM Bundle Upload Parser Helper
  const handleSinglePemBundleUpload = (e) => {
    const file = e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (event) => {
      const content = event.target.result;

      // Extract Certificate Blocks
      const certMatches = content.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) || [];
      if (certMatches.length > 0) {
        setSignedSubCaCertPem(certMatches[0]);
        if (certMatches.length > 1) {
          setParentRootPem(certMatches.slice(1).join('\n'));
        }
      }

      // Extract Private Key Block
      const keyMatch = content.match(/-----BEGIN (?:ENCRYPTED |RSA |EC )?PRIVATE KEY-----[\s\S]*?-----END (?:ENCRYPTED |RSA |EC )?PRIVATE KEY-----/g);
      if (keyMatch && keyMatch.length > 0) {
        setSubCaPrivateKeyPem(keyMatch[0]);
      }
    };
    reader.readAsText(file);
  };

  const handleGenerateSubCaCsr = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch('/api/setup/intermediate-csr', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          caName,
          organization,
          organizationalUnit: ou,
          country,
          state,
          locality,
          algorithm
        })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Failed to generate Sub-CA CSR');
      
      setSubCaCsrPem(data.csrPem);
      setSubCaPrivateKeyPem(data.privateKeyPem);
      setStep(4);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleSubmitSetup = async () => {
    if (passphrase !== confirmPassphrase) {
      setError('Master Passphrase and confirmation do not match.');
      return;
    }
    if (!passphrase || passphrase.length < 6) {
      setError('Master Passphrase must be at least 6 characters long.');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      if (caType === 'root') {
        const res = await fetch('/api/setup/root', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            caName,
            organization,
            organizationalUnit: ou,
            country,
            state,
            locality,
            algorithm,
            validityYears: parseInt(validityYears),
            passphrase
          })
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'Root CA setup failed.');
        onComplete(data.config);
      } else {
        const res = await fetch('/api/setup/intermediate-complete', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            caName,
            organization,
            organizationalUnit: ou,
            country,
            state,
            locality,
            algorithm,
            subCaCertPem: signedSubCaCertPem || subCaCsrPem,
            parentRootCertPem: parentRootPem,
            subCaPrivateKeyPem,
            passphrase,
            parentCrlUrl
          })
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'Intermediate CA setup failed.');
        onComplete(data.config);
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="modal-overlay">
      <div className="modal-card" style={{ maxWidth: '780px' }}>
        <div className="modal-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <Server className="text-blue-600" size={24} style={{ color: 'var(--color-blue)' }} />
            <div>
              <h3 style={{ fontFamily: 'var(--font-heading)', fontSize: '1.2rem', fontWeight: 700 }}>
                Microsoft AD CS Certificate Authority Setup Wizard
              </h3>
              <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                Step {step} of {caType === 'root' ? 4 : 5} — Configure Production PKI Architecture
              </p>
            </div>
          </div>
          {onClose && (
            <button className="btn btn-secondary" style={{ padding: '0.2rem 0.5rem' }} onClick={onClose}>
              ✕
            </button>
          )}
        </div>

        <div className="modal-body">
          {error && (
            <div className="alert alert-danger">
              <AlertCircle size={18} />
              <div>{error}</div>
            </div>
          )}

          {step === 1 && (
            <div>
              <h4 style={{ marginBottom: '0.5rem', fontFamily: 'var(--font-heading)' }}>Select CA Role & Type</h4>
              <p style={{ fontSize: '0.875rem', color: 'var(--text-muted)', marginBottom: '1.5rem' }}>
                Specify whether this instance operates as an isolated Root Authority or a Subordinate Intermediate CA.
              </p>

              <div className="grid-2" style={{ marginBottom: '1.5rem' }}>
                <div
                  onClick={() => setCaType('root')}
                  style={{
                    padding: '1.25rem',
                    borderRadius: '8px',
                    border: caType === 'root' ? '2px solid var(--color-blue)' : '1px solid var(--border-accent)',
                    background: caType === 'root' ? '#eff6ff' : '#ffffff',
                    cursor: 'pointer'
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem' }}>
                    <Shield style={{ color: 'var(--color-blue)' }} size={20} />
                    <strong style={{ fontSize: '1rem', color: 'var(--text-heading)' }}>Standalone Root CA</strong>
                  </div>
                  <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                    Generates a self-signed Root certificate anchor. Recommended for top-level enterprise trust boundaries.
                  </p>
                </div>

                <div
                  onClick={() => setCaType('intermediate')}
                  style={{
                    padding: '1.25rem',
                    borderRadius: '8px',
                    border: caType === 'intermediate' ? '2px solid var(--color-blue)' : '1px solid var(--border-accent)',
                    background: caType === 'intermediate' ? '#eff6ff' : '#ffffff',
                    cursor: 'pointer'
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem' }}>
                    <Key style={{ color: 'var(--color-indigo)' }} size={20} />
                    <strong style={{ fontSize: '1rem', color: 'var(--text-heading)' }}>Subordinate / Intermediate CA</strong>
                  </div>
                  <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                    Generates a Sub-CA CSR or imports a single .pem bundle containing Sub-CA cert, chain, and private key.
                  </p>
                </div>
              </div>
            </div>
          )}

          {step === 2 && (
            <div>
              <h4 style={{ marginBottom: '0.5rem', fontFamily: 'var(--font-heading)' }}>Algorithm & Key Specification</h4>
              <p style={{ fontSize: '0.875rem', color: 'var(--text-muted)', marginBottom: '1.25rem' }}>
                Select cryptographic signature algorithm and key parameters.
              </p>

              <div className="form-group">
                <label className="form-label">Signature & Key Algorithm</label>
                <select className="form-select" value={algorithm} onChange={(e) => setAlgorithm(e.target.value)}>
                  <option value="RSA_2048">RSA 2048-bit</option>
                  <option value="RSA_4096">RSA 4096-bit</option>
                  <option value="ECDSA_P256">ECDSA P-256 (NIST Curve)</option>
                  <option value="ECDSA_P384">ECDSA P-384 (ECC)</option>
                  <option value="ED25519">Ed25519</option>
                </select>
              </div>

              <div className="form-group">
                <label className="form-label">Validity Period (Years)</label>
                <select className="form-select" value={validityYears} onChange={(e) => setValidityYears(e.target.value)}>
                  <option value={10}>10 Years (Root CA Standard)</option>
                  <option value={5}>5 Years (Subordinate CA Standard)</option>
                  <option value={20}>20 Years (Long-Term Infrastructure Root)</option>
                </select>
              </div>
            </div>
          )}

          {step === 3 && (
            <div>
              <h4 style={{ marginBottom: '0.5rem', fontFamily: 'var(--font-heading)' }}>CA Subject Distinguished Name (DN)</h4>
              <p style={{ fontSize: '0.875rem', color: 'var(--text-muted)', marginBottom: '1.25rem' }}>
                Enter organizational details for the CA authority certificate.
              </p>

              <div className="form-group">
                <label className="form-label">CA Common Name (CN)</label>
                <input className="form-input" value={caName} onChange={(e) => setCaName(e.target.value)} required />
              </div>

              <div className="grid-2">
                <div className="form-group">
                  <label className="form-label">Organization (O)</label>
                  <input className="form-input" value={organization} onChange={(e) => setOrganization(e.target.value)} />
                </div>
                <div className="form-group">
                  <label className="form-label">Organizational Unit (OU)</label>
                  <input className="form-input" value={ou} onChange={(e) => setOu(e.target.value)} />
                </div>
              </div>

              <div className="grid-3">
                <div className="form-group">
                  <label className="form-label">Country (C)</label>
                  <input className="form-input" value={country} onChange={(e) => setCountry(e.target.value)} maxLength={2} />
                </div>
                <div className="form-group">
                  <label className="form-label">State / Province</label>
                  <input className="form-input" value={state} onChange={(e) => setState(e.target.value)} />
                </div>
                <div className="form-group">
                  <label className="form-label">Locality / City</label>
                  <input className="form-input" value={locality} onChange={(e) => setLocality(e.target.value)} />
                </div>
              </div>
            </div>
          )}

          {/* STEP 4 FOR INTERMEDIATE CA: SINGLE PEM BUNDLE UPLOAD BUTTON */}
          {step === 4 && caType === 'intermediate' && (
            <div>
              <h4 style={{ marginBottom: '0.5rem', fontFamily: 'var(--font-heading)' }}>Intermediate CA Trust Chain Import</h4>
              <p style={{ fontSize: '0.875rem', color: 'var(--text-muted)', marginBottom: '1.25rem' }}>
                Upload a single .pem bundle file containing the Sub-CA cert, parent Root chain, and private key.
              </p>

              <div className="alert alert-info" style={{ marginBottom: '1rem' }}>
                <Upload size={18} />
                <div>
                  <strong>Single File Bundle Import:</strong> Click the button below to upload a combined <code>.pem</code> file containing all certificate chain blocks and private keys.
                </div>
              </div>

              <div style={{ textAlign: 'center', margin: '1rem 0 1.5rem' }}>
                <label className="btn btn-primary" style={{ padding: '0.75rem 1.5rem', cursor: 'pointer', fontSize: '0.95rem' }}>
                  <Upload size={18} /> Upload Complete Sub-CA Bundle (.pem / .crt)
                  <input type="file" accept=".pem,.crt,.cer,.key" style={{ display: 'none' }} onChange={handleSinglePemBundleUpload} />
                </label>
              </div>

              <div className="form-group">
                <label className="form-label">Parent Root CA CRL Endpoint (For Automatic Revocation Sync)</label>
                <input
                  type="text"
                  className="form-input"
                  value={parentCrlUrl}
                  onChange={(e) => setParentCrlUrl(e.target.value)}
                  placeholder="http://localhost:8088/api/crl"
                />
              </div>

              <div className="form-group">
                <label className="form-label">Signed Subordinate CA Certificate (PEM)</label>
                <textarea
                  className="form-textarea"
                  rows={3}
                  placeholder="-----BEGIN CERTIFICATE-----\n..."
                  value={signedSubCaCertPem}
                  onChange={(e) => setSignedSubCaCertPem(e.target.value)}
                />
              </div>

              <div className="form-group">
                <label className="form-label">Parent Root CA Certificate / Chain (PEM)</label>
                <textarea
                  className="form-textarea"
                  rows={3}
                  placeholder="-----BEGIN CERTIFICATE-----\n..."
                  value={parentRootPem}
                  onChange={(e) => setParentRootPem(e.target.value)}
                />
              </div>
            </div>
          )}

          {((step === 4 && caType === 'root') || (step === 5 && caType === 'intermediate')) && (
            <div>
              <h4 style={{ marginBottom: '0.5rem', fontFamily: 'var(--font-heading)' }}>Master Passphrase & Storage Encryption</h4>
              <p style={{ fontSize: '0.875rem', color: 'var(--text-muted)', marginBottom: '1.25rem' }}>
                Configure a strong Master Passphrase used to encrypt the CA private key with PBKDF2 + AES-256-GCM.
              </p>

              <div className="alert alert-warning">
                <Lock size={18} />
                <div>
                  <strong>Important:</strong> Keep this passphrase safe. It is required to sign new certificates, authorize revocations, and perform CA backups.
                </div>
              </div>

              <div className="form-group">
                <label className="form-label">Master Passphrase</label>
                <input
                  type="password"
                  className="form-input"
                  value={passphrase}
                  onChange={(e) => setPassphrase(e.target.value)}
                  placeholder="••••••••••••••••"
                />
              </div>

              <div className="form-group">
                <label className="form-label">Confirm Master Passphrase</label>
                <input
                  type="password"
                  className="form-input"
                  value={confirmPassphrase}
                  onChange={(e) => setConfirmPassphrase(e.target.value)}
                  placeholder="••••••••••••••••"
                />
              </div>
            </div>
          )}
        </div>

        <div className="modal-footer">
          {step > 1 && (
            <button className="btn btn-secondary" onClick={() => setStep(step - 1)} disabled={loading}>
              Back
            </button>
          )}

          {step < (caType === 'root' ? 4 : 5) ? (
            <button
              className="btn btn-primary"
              onClick={() => {
                if (step === 3 && caType === 'intermediate') {
                  handleGenerateSubCaCsr();
                } else {
                  setStep(step + 1);
                }
              }}
              disabled={loading}
            >
              {loading ? 'Processing...' : 'Next Step'} <ArrowRight size={15} />
            </button>
          ) : (
            <button className="btn btn-emerald" onClick={handleSubmitSetup} disabled={loading}>
              {loading ? 'Initializing CA...' : 'Initialize Certificate Authority'} <Check size={15} />
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
