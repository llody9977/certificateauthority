import React, { useState, useEffect } from 'react';
import {
  Search, Filter, ShieldCheck, Download, AlertTriangle, Key, Clock,
  FileText, CheckCircle, RefreshCw, XCircle, ShieldAlert, GitCommit,
  Layers, ChevronRight, ChevronDown, Upload
} from 'lucide-react';
import { ExportModal } from './ExportModal.jsx';
import { CertImportModal } from './CertImportModal.jsx';

function formatDateTime(dateStr) {
  if (!dateStr) return 'N/A';
  try {
    const d = new Date(dateStr);
    if (isNaN(d.getTime())) return dateStr;
    const year = d.getFullYear();
    const month = String(d.getMonth() + 1).padStart(2, '0');
    const day = String(d.getDate()).padStart(2, '0');
    const hours = String(d.getHours()).padStart(2, '0');
    const mins = String(d.getMinutes()).padStart(2, '0');
    const secs = String(d.getSeconds()).padStart(2, '0');
    return `${year}-${month}-${day} ${hours}:${mins}:${secs}`;
  } catch (e) {
    return dateStr;
  }
}

function getExpiresInText(validTo) {
  if (!validTo) return '-';
  const now = new Date();
  const end = new Date(validTo);
  const diffMs = end - now;
  if (diffMs <= 0) {
    return '-';
  } else {
    const mins = Math.floor(diffMs / (1000 * 60));
    const hours = Math.floor(diffMs / (1000 * 60 * 60));
    const days = Math.floor(diffMs / (1000 * 60 * 60 * 24));
    if (days > 0) return `${days}d`;
    if (hours > 0) return `${hours}h`;
    return `${mins}m`;
  }
}

export function CertExplorer({ caStatus, onRequestNewCert }) {
  const [certs, setCerts] = useState([]);
  const [loading, setLoading] = useState(false);
  const [showImportModal, setShowImportModal] = useState(false);
  const [viewMode, setViewMode] = useState('flat'); // 'flat' | 'grouped'
  const [expandedGroups, setExpandedGroups] = useState({});

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
  const [revokeMode, setRevokeMode] = useState('revoke_only'); // 'revoke_only' | 'revoke_reissue'
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

  const toggleGroup = (cn) => {
    setExpandedGroups(prev => ({ ...prev, [cn]: !prev[cn] }));
  };

  const handleToggleAutoRenew = async (cert, enable) => {
    try {
      const res = await fetch(`/api/certificates/${cert.id}/auto-renew`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: enable })
      });
      if (res.ok) {
        fetchCertificates();
      }
    } catch (err) {
      console.error('Error toggling auto-renew:', err);
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

      if (revokeMode === 'revoke_reissue') {
        const reissueRes = await fetch('/api/certificates/issue', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            commonName: revokeModalCert.commonName,
            certType: revokeModalCert.certType || 'web_server',
            profile: revokeModalCert.profile || 'standard',
            validityDays: 365,
            algorithm: revokeModalCert.algorithm || 'RSA_2048',
            sans: revokeModalCert.sans || [],
            masterPassphrase: revokePassphrase
          })
        });
        const reissueData = await reissueRes.json();
        if (!reissueRes.ok) {
          throw new Error(`Revocation succeeded, but replacement certificate issuance failed: ${reissueData.error}`);
        }
      }

      setRevokeModalCert(null);
      setRevokePassphrase('');
      setRevokeDetails('');
      setRevokeMode('revoke_only');
      fetchCertificates();
    } catch (err) {
      setRevokeError(err.message);
    } finally {
      setRevokeLoading(false);
    }
  };

  // Group certificates by Common Name for Lineage Tree View
  const groupedCertificates = certs.reduce((acc, cert) => {
    const cn = cert.commonName || 'Unlabeled';
    if (!acc[cn]) acc[cn] = [];
    acc[cn].push(cert);
    return acc;
  }, {});

  const renderCertRow = (cert, isNested = false) => {
    const isExpired = cert.effectiveStatus === 'EXPIRED' || cert.status === 'EXPIRED';
    const isRevoked = cert.effectiveStatus === 'REVOKED' || cert.status === 'REVOKED';
    const isChainRevoked = cert.effectiveStatus === 'CHAIN_REVOKED';
    const isActive = cert.effectiveStatus === 'ACTIVE';

    const expiresInText = getExpiresInText(cert.validTo);

    return (
      <tr key={cert.id} style={{ background: isNested ? '#f8fafc' : 'inherit' }}>
        <td style={{ paddingLeft: isNested ? '2.5rem' : '1rem' }}>
          {isActive ? (
            <span className="badge badge-emerald">
              <CheckCircle size={12} /> Active
            </span>
          ) : isExpired ? (
            <span className="badge" style={{ backgroundColor: '#fff7ed', color: '#c2410c', border: '1px solid #ffedd5' }}>
              <Clock size={12} /> Expired
            </span>
          ) : isChainRevoked ? (
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
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', flexWrap: 'wrap' }}>
            <strong style={{ color: 'var(--text-heading)' }}>{cert.commonName}</strong>
            {cert.isRenewed && (
              <span className="badge badge-indigo" title={`Renewed by Serial ${cert.renewedBySerial}`} style={{ fontSize: '0.675rem', padding: '0.15rem 0.35rem' }}>
                <RefreshCw size={10} /> Renewed
              </span>
            )}
            {cert.autoRenew ? (
              <span
                className="badge badge-emerald"
                style={{ cursor: 'pointer', fontSize: '0.65rem', padding: '0.15rem 0.35rem' }}
                title="Auto-Renew Enabled (Click to disable)"
                onClick={() => handleToggleAutoRenew(cert, false)}
              >
                <RefreshCw size={9} /> Auto-Renew On
              </span>
            ) : (
              <span
                className="badge badge-secondary"
                style={{ cursor: 'pointer', fontSize: '0.65rem', padding: '0.15rem 0.35rem', opacity: 0.75 }}
                title="Click to Enable Auto-Renew"
                onClick={() => handleToggleAutoRenew(cert, true)}
              >
                + Auto-Renew
              </span>
            )}
          </div>
          {cert.sans && cert.sans.length > 0 && (
            <small style={{ color: 'var(--text-dim)', fontFamily: 'var(--font-mono)', fontSize: '0.725rem', display: 'block' }}>
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
          <small style={{ display: 'block', color: 'var(--text-heading)', fontWeight: 600, fontFamily: 'var(--font-mono)', fontSize: '0.725rem' }}>
            To: {formatDateTime(cert.validTo)}
          </small>
          <small style={{ display: 'block', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)', fontSize: '0.675rem' }}>
            From: {formatDateTime(cert.validFrom || cert.issuedAt)}
          </small>
        </td>
        <td>
          <span className={`badge ${isExpired ? 'badge-rose' : isActive ? 'badge-cyan' : 'badge-amber'}`} style={{ fontFamily: 'var(--font-mono)', fontSize: '0.725rem' }}>
            {expiresInText}
          </span>
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
            
            {/* Export available ONLY for ACTIVE certificates */}
            {isActive ? (
              <button
                className="btn btn-primary"
                style={{ padding: '0.25rem 0.5rem', fontSize: '0.75rem' }}
                onClick={() => setExportCert(cert)}
              >
                <Download size={12} /> Export
              </button>
            ) : (
              <button
                className="btn btn-secondary"
                style={{ padding: '0.25rem 0.5rem', fontSize: '0.75rem', opacity: 0.5, cursor: 'not-allowed' }}
                title="Export disabled for Expired / Revoked certificates"
                disabled
              >
                <Download size={12} /> Export
              </button>
            )}

            {isActive && (
              <button
                className="btn btn-danger"
                style={{ padding: '0.25rem 0.5rem', fontSize: '0.75rem' }}
                onClick={() => {
                  setRevokeModalCert(cert);
                  setRevokeMode('revoke_only');
                }}
              >
                Revoke
              </button>
            )}
          </div>
        </td>
      </tr>
    );
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
          <div style={{ display: 'flex', gap: '1rem', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap' }}>
            <div style={{ position: 'relative', flex: 1, minWidth: '260px' }}>
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

            <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
              <select className="form-select" style={{ width: '150px' }} value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)}>
                <option value="">All Statuses</option>
                <option value="ACTIVE">ACTIVE</option>
                <option value="EXPIRED">EXPIRED</option>
                <option value="REVOKED">REVOKED</option>
              </select>

              <select className="form-select" style={{ width: '160px' }} value={typeFilter} onChange={(e) => setTypeFilter(e.target.value)}>
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

              {/* View Mode Toggle: Flat List vs Nested Renewal Lineage Groups */}
              <div style={{ display: 'flex', background: '#f1f5f9', padding: '0.2rem', borderRadius: '6px', border: '1px solid var(--border-subtle)' }}>
                <button
                  className={`btn ${viewMode === 'flat' ? 'btn-primary' : 'btn-secondary'}`}
                  style={{ padding: '0.25rem 0.6rem', fontSize: '0.75rem' }}
                  onClick={() => setViewMode('flat')}
                >
                  Flat List
                </button>
                <button
                  className={`btn ${viewMode === 'grouped' ? 'btn-primary' : 'btn-secondary'}`}
                  style={{ padding: '0.25rem 0.6rem', fontSize: '0.75rem' }}
                  onClick={() => setViewMode('grouped')}
                >
                  <GitCommit size={12} /> Lineage View
                </button>
              </div>
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
              <th>Validity Dates</th>
              <th>Expires In</th>
              <th style={{ textAlign: 'right' }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr>
                <td colSpan={8} style={{ textAlign: 'center', padding: '2rem' }}>
                  Loading certificates...
                </td>
              </tr>
            ) : certs.length === 0 ? (
              <tr>
                <td colSpan={8} style={{ textAlign: 'center', padding: '2.5rem', color: 'var(--text-muted)' }}>
                  No certificates found matching criteria.
                </td>
              </tr>
            ) : viewMode === 'flat' ? (
              certs.map(cert => renderCertRow(cert, false))
            ) : (
              // Grouped / Nested Renewal Lineage View
              Object.entries(groupedCertificates).map(([cn, groupCerts]) => {
                const isExpanded = expandedGroups[cn] ?? true;
                const headCert = groupCerts.find(c => c.effectiveStatus === 'ACTIVE') || groupCerts[0];
                const predecessors = groupCerts.filter(c => c.id !== headCert.id);

                return (
                  <React.Fragment key={cn}>
                    {/* Group Header Row */}
                    <tr style={{ background: '#f1f5f9', borderTop: '2px solid var(--border-subtle)', fontWeight: 600 }}>
                      <td colSpan={8} style={{ padding: '0.6rem 1rem' }}>
                        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                            <button
                              className="btn btn-secondary"
                              style={{ padding: '0.15rem 0.35rem', fontSize: '0.7rem' }}
                              onClick={() => toggleGroup(cn)}
                            >
                              {isExpanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                            </button>
                            <GitCommit size={16} color="var(--color-indigo)" />
                            <strong style={{ fontSize: '0.95rem', color: 'var(--text-heading)' }}>{cn}</strong>
                            <span className="badge badge-cyan" style={{ fontSize: '0.7rem' }}>
                              {groupCerts.length} {groupCerts.length === 1 ? 'Certificate Version' : 'Lineage Versions'}
                            </span>
                          </div>
                          <small style={{ color: 'var(--text-muted)' }}>
                            Active Version SN: {headCert.serialNumber}
                          </small>
                        </div>
                      </td>
                    </tr>

                    {/* Render Head Certificate & Predecessor Children if expanded */}
                    {isExpanded && (
                      <>
                        {renderCertRow(headCert, false)}
                        {predecessors.map(pred => renderCertRow(pred, true))}
                      </>
                    )}
                  </React.Fragment>
                );
              })
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
                  <div
                    className={`alert ${
                      chainData.validTrustChain
                        ? 'alert-success'
                        : chainCert.effectiveStatus === 'EXPIRED' || chainCert.status === 'EXPIRED'
                        ? 'alert-warning'
                        : 'alert-danger'
                    }`}
                    style={{ marginBottom: '1.25rem' }}
                  >
                    {chainData.validTrustChain ? (
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                        <CheckCircle size={18} />
                        <div><strong>TRUST CHAIN VALID:</strong> Certificate chains to an active trusted Root Authority.</div>
                      </div>
                    ) : chainCert.effectiveStatus === 'EXPIRED' || chainCert.status === 'EXPIRED' ? (
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                        <Clock size={18} />
                        <div><strong>CERTIFICATE EXPIRED:</strong> The certificate validity period ended on {formatDateTime(chainCert.validTo)}.</div>
                      </div>
                    ) : chainCert.effectiveStatus === 'CHAIN_REVOKED' ? (
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                        <ShieldAlert size={18} />
                        <div><strong>TRUST CHAIN REVOKED:</strong> The issuing Parent Sub-CA certificate has been revoked by Root Authority.</div>
                      </div>
                    ) : (
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                        <XCircle size={18} />
                        <div><strong>CERTIFICATE REVOKED:</strong> This end-entity certificate has been explicitly revoked.</div>
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
                          justifyContent: 'space-between',
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
                    {selectedCert.effectiveStatus === 'ACTIVE' ? (
                      <span className="badge badge-emerald">ACTIVE</span>
                    ) : selectedCert.effectiveStatus === 'EXPIRED' || selectedCert.status === 'EXPIRED' ? (
                      <span className="badge" style={{ backgroundColor: '#fff7ed', color: '#c2410c', border: '1px solid #ffedd5' }}>EXPIRED</span>
                    ) : selectedCert.effectiveStatus === 'CHAIN_REVOKED' ? (
                      <span className="badge badge-amber">CHAIN REVOKED</span>
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

              {/* Export Button restricted ONLY to ACTIVE certificates */}
              {selectedCert.effectiveStatus === 'ACTIVE' ? (
                <button
                  className="btn btn-primary"
                  onClick={() => {
                    setExportCert(selectedCert);
                    setSelectedCert(null);
                  }}
                >
                  <Download size={14} /> Export Options
                </button>
              ) : (
                <button
                  className="btn btn-secondary"
                  style={{ opacity: 0.5, cursor: 'not-allowed' }}
                  title="Export disabled for Expired or Revoked certificates"
                  disabled
                >
                  <Download size={14} /> Export Options (Disabled)
                </button>
              )}
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
                <label className="form-label">Revocation Workflow Action</label>
                <div style={{ display: 'flex', gap: '1.25rem', marginTop: '0.35rem' }}>
                  <label style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.875rem', cursor: 'pointer' }}>
                    <input
                      type="radio"
                      name="revokeMode"
                      value="revoke_only"
                      checked={revokeMode === 'revoke_only'}
                      onChange={() => setRevokeMode('revoke_only')}
                    />
                    Revoke Only
                  </label>
                  <label style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.875rem', cursor: 'pointer' }}>
                    <input
                      type="radio"
                      name="revokeMode"
                      value="revoke_reissue"
                      checked={revokeMode === 'revoke_reissue'}
                      onChange={() => setRevokeMode('revoke_reissue')}
                    />
                    <RefreshCw size={14} color="var(--color-indigo)" /> Revoke & Re-issue Replacement Certificate
                  </label>
                </div>
              </div>

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
                  placeholder="e.g. Key compromise recovery or server decommissioned"
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
                {revokeLoading ? 'Processing...' : revokeMode === 'revoke_reissue' ? 'Revoke & Issue Replacement' : 'Confirm Revocation'}
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

export default CertExplorer;
