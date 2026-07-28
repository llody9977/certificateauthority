import React, { useState, useEffect } from 'react';
import { Search, Filter, ShieldCheck, Download, AlertTriangle, Key, Clock, FileText, CheckCircle, RefreshCw, XCircle, ShieldAlert, GitCommit, Layers } from 'lucide-react';
import { ExportModal } from './ExportModal.jsx';
import { CertImportModal } from './CertImportModal.jsx';
import { Upload } from 'lucide-react';

export function CertExplorer({ caStatus, onRequestNewCert }) {
  const [certs, setCerts] = useState([]);
  const [loading, setLoading] = useState(false);
  const [showImportModal, setShowImportModal] = useState(false);
  
  // Search & Filter state
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [typeFilter, setTypeFilter] = useState('');
  const [profileFilter, setProfileFilter] = useState('');
  const [algorithmFilter, setAlgorithmFilter] = useState('');

  // Selected cert for modal
  const [selectedCert, setSelectedCert] = useState(null);
  const [exportCert, setExportCert] = useState(null);
  const [chainCert, setChainCert] = useState(null);
  const [chainData, setChainData] = useState(null);
  const [chainLoading, setChainLoading] = useState(false);

  // Revocation Modal state
  const [revokeModalCert, setRevokeModalCert] = useState(null);
  const [revokeReason, setRevokeReason] = useState('0');
  const [revokeDetails, setRevokeDetails] = useState('');
  const [revokePassphrase, setRevokePassphrase] = useState('');
  const [revokeLoading, setRevokeLoading] = useState(false);
  const [revokeError, setRevokeError] = useState(null);

  const [cacheStats, setCacheStats] = useState(null);

  const fetchCertificates = async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams();
      if (searchQuery) params.append('query', searchQuery);
      if (statusFilter) params.append('status', statusFilter);
      if (typeFilter) params.append('certType', typeFilter);
      if (profileFilter) params.append('profile', profileFilter);
      if (algorithmFilter) params.append('algorithm', algorithmFilter);

      const res = await fetch(`/api/certificates?${params.toString()}`);
      const data = await res.json();
      if (res.ok) {
        setCerts(data.certificates || []);
        if (data.revocationCacheStats) {
          setCacheStats(data.revocationCacheStats);
        }
      }
    } catch (err) {
      console.error('Error fetching certificates:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchCertificates();
  }, [searchQuery, statusFilter, typeFilter, profileFilter, algorithmFilter]);

  const handleInspectChain = async (cert) => {
    setChainCert(cert);
    setChainLoading(true);
    try {
      const res = await fetch(`/api/certificates/${cert.id}/chain`);
      const data = await res.json();
      if (res.ok) {
        setChainData(data);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setChainLoading(false);
    }
  };

  const handleRevokeSubmit = async () => {
    setRevokeLoading(true);
    setRevokeError(null);

    try {
      const res = await fetch('/api/certificates/revoke', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          certId: revokeModalCert.id,
          reasonCode: revokeReason,
          revocationDetails: revokeDetails,
          masterPassphrase: revokePassphrase
        })
      });

      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Failed to revoke certificate');

      setRevokeModalCert(null);
      setRevokePassphrase('');
      setRevokeDetails('');
      fetchCertificates();
    } catch (err) {
      setRevokeError(err.message);
    } finally {
      setRevokeLoading(false);
    }
  };

  return (
    <div>
      {/* Header Banner */}
      <div className="panel" style={{ background: '#ffffff', marginBottom: '1.25rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div>
            <h2 style={{ fontFamily: 'var(--font-heading)', fontSize: '1.5rem', fontWeight: 800, color: 'var(--text-heading)' }}>
              Certificate Management Directory
            </h2>
            <p style={{ fontSize: '0.875rem', color: 'var(--text-muted)' }}>
              Search, filter, inspect trust chains, export, and revoke x509 certificates issued by {caStatus?.config?.caName || 'step-ca Engine'}.
            </p>
          </div>
          <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
            {cacheStats && (
              <span className="badge badge-cyan" title="5-minute TTL Revocation Cache optimizes API & DB performance">
                ⚡ Revocation Cache: {cacheStats.cached ? `Hit (${cacheStats.cacheAgeSeconds}s old)` : 'Refreshed'} • TTL 300s
              </span>
            )}
            <button className="btn btn-secondary" onClick={() => setShowImportModal(true)} style={{ fontSize: '0.85rem' }}>
              <Upload size={14} /> Import External Cert
            </button>
            <button className="btn btn-primary" onClick={onRequestNewCert}>
              + Issue New Certificate
            </button>
          </div>
        </div>

        <CertImportModal
          isOpen={showImportModal}
          onClose={() => setShowImportModal(false)}
          onImportSuccess={() => fetchCertificates()}
        />

        {/* Search & Multi-field Filter Controls */}
        <div style={{ marginTop: '1.25rem', paddingTop: '1.25rem', borderTop: '1px solid var(--border-subtle)' }}>
          <div className="grid-4" style={{ alignItems: 'center' }}>
            <div style={{ position: 'relative', gridColumn: 'span 2' }}>
              <Search size={16} style={{ position: 'absolute', left: '12px', top: '12px', color: 'var(--text-dim)' }} />
              <input
                type="text"
                className="form-input"
                style={{ paddingLeft: '2.3rem' }}
                placeholder="Search by Common Name, SAN, Serial Number, or Thumbprint..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
              />
            </div>

            <div>
              <select className="form-select" value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)}>
                <option value="">All Statuses</option>
                <option value="ACTIVE">ACTIVE</option>
                <option value="REVOKED">REVOKED</option>
              </select>
            </div>

            <div>
              <select className="form-select" value={typeFilter} onChange={(e) => setTypeFilter(e.target.value)}>
                <option value="">All Cert Types</option>
                <option value="web_server">Web Server (TLS)</option>
                <option value="acme_tls">ACME Protocol TLS</option>
                <option value="client_auth">Client Auth</option>
                <option value="mtls">mTLS Mutual</option>
                <option value="code_signing">Code Signing</option>
                <option value="smime">S/MIME Email</option>
                <option value="ocsp_signer">OCSP Signer</option>
                <option value="sub_ca">Sub-CA</option>
              </select>
            </div>
          </div>
        </div>
      </div>

      {/* Certificates Table */}
      <div className="panel" style={{ padding: 0, overflow: 'hidden' }}>
        <table className="data-table">
          <thead>
            <tr>
              <th>Status</th>
              <th>Common Name / Subject</th>
              <th>Type / Profile</th>
              <th>Algorithm</th>
              <th>Serial & Fingerprint</th>
              <th>Validity</th>
              <th style={{ textAlign: 'right' }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr>
                <td colSpan={7} style={{ textAlign: 'center', padding: '2rem' }}>
                  Loading certificates...
                </td>
              </tr>
            ) : certs.length === 0 ? (
              <tr>
                <td colSpan={7} style={{ textAlign: 'center', padding: '2.5rem', color: 'var(--text-muted)' }}>
                  No certificates found matching criteria.
                </td>
              </tr>
            ) : (
              certs.map((cert) => (
                <tr key={cert.id}>
                  <td>
                    {cert.effectiveStatus === 'ACTIVE' ? (
                      <span className="badge badge-emerald">
                        <CheckCircle size={12} /> Active
                      </span>
                    ) : cert.effectiveStatus === 'CHAIN_REVOKED' ? (
                      <span className="badge badge-amber" title="Parent Sub-CA has been revoked by Root Authority">
                        <ShieldAlert size={12} /> Chain Revoked
                      </span>
                    ) : (
                      <span className="badge badge-rose">
                        <XCircle size={12} /> Revoked
                      </span>
                    )}
                  </td>
                  <td>
                    <strong style={{ color: 'var(--text-heading)', display: 'block' }}>{cert.commonName}</strong>
                    {cert.sans && cert.sans.length > 0 && (
                      <small style={{ color: 'var(--text-dim)', fontFamily: 'var(--font-mono)', fontSize: '0.725rem' }}>
                        SANs: {cert.sans.slice(0, 2).join(', ')}{cert.sans.length > 2 ? ` +${cert.sans.length - 2} more` : ''}
                      </small>
                    )}
                  </td>
                  <td>
                    <span className="badge badge-indigo" style={{ marginRight: '0.35rem' }}>
                      {cert.certType}
                    </span>
                    <span className="badge badge-cyan">{cert.profile}</span>
                  </td>
                  <td>
                    <span className="code-inline">{cert.algorithm}</span>
                  </td>
                  <td>
                    <small style={{ display: 'block', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
                      SN: {cert.serialNumber}
                    </small>
                    <small style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-dim)', fontSize: '0.675rem' }}>
                      {cert.fingerprint?.substring(0, 18)}...
                    </small>
                  </td>
                  <td>
                    <small style={{ display: 'block', color: 'var(--text-muted)' }}>
                      To: {new Date(cert.validTo).toLocaleDateString()}
                    </small>
                  </td>
                  <td style={{ textAlign: 'right' }}>
                    <div style={{ display: 'flex', gap: '0.35rem', justifyContent: 'flex-end' }}>
                      <button
                        className="btn btn-secondary"
                        style={{ padding: '0.25rem 0.5rem', fontSize: '0.75rem' }}
                        title="Inspect Trust Chain"
                        onClick={() => handleInspectChain(cert)}
                      >
                        <Layers size={12} /> Chain
                      </button>
                      <button
                        className="btn btn-secondary"
                        style={{ padding: '0.25rem 0.5rem', fontSize: '0.75rem' }}
                        onClick={() => setSelectedCert(cert)}
                      >
                        Inspect
                      </button>
                      <button
                        className="btn btn-primary"
                        style={{ padding: '0.25rem 0.5rem', fontSize: '0.75rem' }}
                        onClick={() => setExportCert(cert)}
                      >
                        <Download size={12} /> Export
                      </button>
                      {cert.status === 'ACTIVE' && (
                        <button
                          className="btn btn-danger"
                          style={{ padding: '0.25rem 0.5rem', fontSize: '0.75rem' }}
                          onClick={() => setRevokeModalCert(cert)}
                        >
                          Revoke
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* INSPECT TRUST CHAIN MODAL */}
      {chainCert && (
        <div className="modal-overlay">
          <div className="modal-card">
            <div className="modal-header">
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <Layers size={20} style={{ color: 'var(--color-blue)' }} />
                <h3 style={{ fontFamily: 'var(--font-heading)', fontWeight: 700 }}>
                  Certificate Trust Chain — {chainCert.commonName}
                </h3>
              </div>
              <button className="btn btn-secondary" style={{ padding: '0.2rem 0.5rem' }} onClick={() => setChainCert(null)}>
                ✕
              </button>
            </div>

            <div className="modal-body">
              {chainLoading ? (
                <p>Analyzing trust chain...</p>
              ) : chainData ? (
                <div>
                  <div className={`alert ${chainData.validTrustChain ? 'alert-success' : 'alert-danger'}`} style={{ marginBottom: '1.25rem' }}>
                    {chainData.validTrustChain ? (
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                        <CheckCircle size={18} />
                        <div><strong>TRUST CHAIN VALID:</strong> Certificate chains to an active trusted Root Authority.</div>
                      </div>
                    ) : (
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                        <ShieldAlert size={18} />
                        <div><strong>TRUST CHAIN REVOKED / INVALID:</strong> Parent Sub-CA or End-Entity certificate is revoked.</div>
                      </div>
                    )}
                  </div>

                  {/* Visual Chain Diagram */}
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem', position: 'relative' }}>
                    {chainData.chain.map((node, index) => (
                      <div
                        key={index}
                        style={{
                          background: node.status === 'REVOKED' ? '#fff1f2' : '#f8fafc',
                          border: node.status === 'REVOKED' ? '1px solid #fecdd3' : '1px solid var(--border-accent)',
                          padding: '1rem',
                          borderRadius: '8px',
                          display: 'flex',
                          justify: 'space-between',
                          alignItems: 'center'
                        }}
                      >
                        <div>
                          <small style={{ color: 'var(--text-dim)', textTransform: 'uppercase', fontSize: '0.7rem', fontWeight: 600 }}>
                            {node.level === 'END_ENTITY' ? 'End-Entity Leaf Certificate' : node.level === 'ISSUING_CA' ? 'Issuing CA Authority' : 'Root Trust Anchor'}
                          </small>
                          <strong style={{ display: 'block', fontSize: '1rem', color: 'var(--text-heading)' }}>{node.commonName}</strong>
                          <small style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>SN: {node.serialNumber}</small>
                        </div>
                        <div>
                          {node.status === 'ACTIVE' ? (
                            <span className="badge badge-emerald">ACTIVE TRUST</span>
                          ) : (
                            <span className="badge badge-rose">REVOKED</span>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              ) : null}
            </div>

            <div className="modal-footer">
              <button className="btn btn-secondary" onClick={() => setChainCert(null)}>
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* INSPECT DETAIL MODAL */}
      {selectedCert && (
        <div className="modal-overlay">
          <div className="modal-card">
            <div className="modal-header">
              <h3 style={{ fontFamily: 'var(--font-heading)', fontWeight: 700 }}>
                Certificate Detail — {selectedCert.commonName}
              </h3>
              <button className="btn btn-secondary" style={{ padding: '0.2rem 0.5rem' }} onClick={() => setSelectedCert(null)}>
                ✕
              </button>
            </div>
            <div className="modal-body">
              <div className="grid-2" style={{ marginBottom: '1rem' }}>
                <div>
                  <small className="form-label">Status</small>
                  <div>
                    {selectedCert.status === 'ACTIVE' ? (
                      <span className="badge badge-emerald">ACTIVE</span>
                    ) : (
                      <span className="badge badge-rose">REVOKED</span>
                    )}
                  </div>
                </div>
                <div>
                  <small className="form-label">Algorithm</small>
                  <span className="code-inline">{selectedCert.algorithm}</span>
                </div>
              </div>

              <div className="form-group">
                <small className="form-label">SHA-256 Fingerprint / Thumbprint</small>
                <div className="code-block" style={{ fontSize: '0.75rem' }}>
                  {selectedCert.fingerprint}
                </div>
              </div>

              <div className="form-group">
                <small className="form-label">Subject Alternative Names (SANs)</small>
                <div style={{ display: 'flex', gap: '0.35rem', flexWrap: 'wrap' }}>
                  {selectedCert.sans?.map((san, idx) => (
                    <span key={idx} className="badge badge-cyan">
                      {san}
                    </span>
                  ))}
                </div>
              </div>

              <div className="form-group">
                <small className="form-label">PEM Certificate Content</small>
                <textarea className="form-textarea" rows={6} value={selectedCert.certPem} readOnly />
              </div>
            </div>
            <div className="modal-footer">
              <button className="btn btn-secondary" onClick={() => setSelectedCert(null)}>
                Close
              </button>
              <button
                className="btn btn-primary"
                onClick={() => {
                  setExportCert(selectedCert);
                  setSelectedCert(null);
                }}
              >
                <Download size={14} /> Export Options
              </button>
            </div>
          </div>
        </div>
      )}

      {/* REVOCATION MODAL */}
      {revokeModalCert && (
        <div className="modal-overlay">
          <div className="modal-card">
            <div className="modal-header" style={{ background: '#fff1f2' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--color-rose)' }}>
                <ShieldAlert size={20} />
                <h3 style={{ fontFamily: 'var(--font-heading)', fontWeight: 700 }}>
                  Revoke Certificate — {revokeModalCert.commonName}
                </h3>
              </div>
              <button className="btn btn-secondary" style={{ padding: '0.2rem 0.5rem' }} onClick={() => setRevokeModalCert(null)}>
                ✕
              </button>
            </div>
            <div className="modal-body">
              {revokeError && (
                <div className="alert alert-danger">
                  <div>{revokeError}</div>
                </div>
              )}

              <p style={{ fontSize: '0.875rem', color: 'var(--text-muted)', marginBottom: '1rem' }}>
                Revoking this certificate will publish its serial number (<code className="code-inline">{revokeModalCert.serialNumber}</code>) to the CA Certificate Revocation List (CRL).
              </p>

              <div className="form-group">
                <label className="form-label">RFC 5280 Revocation Reason Code</label>
                <select className="form-select" value={revokeReason} onChange={(e) => setRevokeReason(e.target.value)}>
                  <option value="0">0: Unspecified</option>
                  <option value="1">1: Key Compromise</option>
                  <option value="2">2: CA Compromise</option>
                  <option value="3">3: Affiliation Changed</option>
                  <option value="4">4: Superseded</option>
                  <option value="5">5: Cessation of Operation</option>
                  <option value="6">6: Certificate Hold</option>
                </select>
              </div>

              <div className="form-group">
                <label className="form-label">Revocation Notes / Justification</label>
                <input
                  type="text"
                  className="form-input"
                  placeholder="e.g. Server decommissioned or private key compromised"
                  value={revokeDetails}
                  onChange={(e) => setRevokeDetails(e.target.value)}
                />
              </div>

              {!caStatus?.sessionUnlocked && (
                <div className="form-group">
                  <label className="form-label">Master Passphrase Authorization</label>
                  <input
                    type="password"
                    className="form-input"
                    placeholder="Enter Master Passphrase"
                    value={revokePassphrase}
                    onChange={(e) => setRevokePassphrase(e.target.value)}
                  />
                </div>
              )}
            </div>
            <div className="modal-footer">
              <button className="btn btn-secondary" onClick={() => setRevokeModalCert(null)}>
                Cancel
              </button>
              <button className="btn btn-danger" onClick={handleRevokeSubmit} disabled={revokeLoading}>
                {revokeLoading ? 'Revoking...' : 'Confirm Revocation'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* EXPORT MODAL */}
      {exportCert && <ExportModal cert={exportCert} onClose={() => setExportCert(null)} />}
    </div>
  );
}
