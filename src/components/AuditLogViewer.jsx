import React, { useState, useEffect } from 'react';
import { Activity, Search, ShieldAlert, CheckCircle, Download, FileText, Filter, Eye } from 'lucide-react';

export function AuditLogViewer() {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [actionFilter, setActionFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('');

  const [selectedLog, setSelectedLog] = useState(null);

  const fetchAuditLogs = async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams();
      if (searchQuery) params.append('query', searchQuery);
      if (actionFilter) params.append('action', actionFilter);
      if (statusFilter) params.append('status', statusFilter);

      const res = await fetch(`/api/audit-logs?${params.toString()}`);
      const data = await res.json();
      if (res.ok) {
        setLogs(data.auditLogs || []);
      }
    } catch (err) {
      console.error('Error fetching audit logs:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAuditLogs();
  }, [searchQuery, actionFilter, statusFilter]);

  const handleExportCsv = () => {
    const headers = ['ID', 'Timestamp', 'Action', 'Actor', 'Target', 'Status', 'Details'];
    const rows = logs.map(l => [
      l.id,
      l.timestamp,
      l.action,
      l.actor,
      l.target,
      l.status,
      JSON.stringify(l.details).replace(/"/g, '""')
    ]);
    const csvContent = 'data:text/csv;charset=utf-8,' + [headers.join(','), ...rows.map(e => e.join(','))].join('\n');
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement('a');
    link.setAttribute('href', encodedUri);
    link.setAttribute('download', `audit_logs_${Date.now()}.csv`);
    document.body.appendChild(link);
    link.click();
    link.remove();
  };

  return (
    <div>
      <div className="panel">
        <div className="panel-header">
          <div>
            <h2 className="panel-title">
              <Activity style={{ color: 'var(--color-blue)' }} size={22} />
              Compliance & Audit Log Trail
            </h2>
            <p className="panel-description">
              Tamper-evident, immutable audit trail of every CA initialization, certificate issuance, revocation, OPA policy change, and export.
            </p>
          </div>
          <button className="btn btn-secondary" onClick={handleExportCsv}>
            <Download size={14} /> Export Audit Log CSV
          </button>
        </div>

        {/* Filter & Search Bar */}
        <div className="grid-3" style={{ marginBottom: '1.25rem' }}>
          <div style={{ position: 'relative', gridColumn: 'span 1' }}>
            <Search size={16} style={{ position: 'absolute', left: '12px', top: '12px', color: 'var(--text-dim)' }} />
            <input
              type="text"
              className="form-input"
              style={{ paddingLeft: '2.3rem' }}
              placeholder="Search audit trail by keyword, actor, target..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
          </div>

          <div>
            <select className="form-select" value={actionFilter} onChange={(e) => setActionFilter(e.target.value)}>
              <option value="">All Actions</option>
              <option value="INITIALIZE_ROOT_CA">INITIALIZE_ROOT_CA</option>
              <option value="INITIALIZE_INTERMEDIATE_CA">INITIALIZE_INTERMEDIATE_CA</option>
              <option value="ISSUE_CERTIFICATE">ISSUE_CERTIFICATE</option>
              <option value="REVOKE_CERTIFICATE">REVOKE_CERTIFICATE</option>
              <option value="UPDATE_OPA_POLICY">UPDATE_OPA_POLICY</option>
              <option value="EXPORT_PKCS12">EXPORT_PKCS12</option>
              <option value="CREATE_CSR">CREATE_CSR</option>
            </select>
          </div>

          <div>
            <select className="form-select" value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)}>
              <option value="">All Statuses</option>
              <option value="SUCCESS">SUCCESS</option>
              <option value="DENIED_BY_OPA">DENIED_BY_OPA</option>
              <option value="FAILED">FAILED</option>
            </select>
          </div>
        </div>

        {/* Audit Log Table */}
        <div style={{ overflowX: 'auto' }}>
          <table className="data-table">
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Action</th>
                <th>Status</th>
                <th>Actor</th>
                <th>Target Resource</th>
                <th>Details Overview</th>
                <th style={{ textAlign: 'right' }}>Inspect</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td colSpan={7} style={{ textAlign: 'center', padding: '2rem' }}>
                    Loading audit trail...
                  </td>
                </tr>
              ) : logs.length === 0 ? (
                <tr>
                  <td colSpan={7} style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-muted)' }}>
                    No audit records found.
                  </td>
                </tr>
              ) : (
                logs.map((log) => (
                  <tr key={log.id}>
                    <td>
                      <small style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-dim)' }}>
                        {new Date(log.timestamp).toLocaleString()}
                      </small>
                    </td>
                    <td>
                      <span className="code-inline" style={{ fontWeight: 600 }}>
                        {log.action}
                      </span>
                    </td>
                    <td>
                      {log.status === 'SUCCESS' ? (
                        <span className="badge badge-emerald">SUCCESS</span>
                      ) : log.status === 'DENIED_BY_OPA' ? (
                        <span className="badge badge-amber">OPA DENIED</span>
                      ) : (
                        <span className="badge badge-rose">FAILED</span>
                      )}
                    </td>
                    <td>
                      <span style={{ fontSize: '0.825rem', color: 'var(--text-body)' }}>{log.actor}</span>
                    </td>
                    <td>
                      <strong style={{ color: 'var(--text-heading)', fontSize: '0.85rem' }}>{log.target}</strong>
                    </td>
                    <td>
                      <small style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', fontSize: '0.725rem' }}>
                        {JSON.stringify(log.details).substring(0, 45)}...
                      </small>
                    </td>
                    <td style={{ textAlign: 'right' }}>
                      <button
                        className="btn btn-secondary"
                        style={{ padding: '0.2rem 0.5rem', fontSize: '0.75rem' }}
                        onClick={() => setSelectedLog(log)}
                      >
                        <Eye size={12} /> View
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Log Detail Inspector Modal */}
      {selectedLog && (
        <div className="modal-overlay">
          <div className="modal-card">
            <div className="modal-header">
              <h3 style={{ fontFamily: 'var(--font-heading)', fontWeight: 700 }}>
                Audit Record — {selectedLog.id}
              </h3>
              <button className="btn btn-secondary" style={{ padding: '0.2rem 0.5rem' }} onClick={() => setSelectedLog(null)}>
                ✕
              </button>
            </div>
            <div className="modal-body">
              <div className="grid-2" style={{ marginBottom: '1rem' }}>
                <div>
                  <small className="form-label">Action</small>
                  <span className="code-inline">{selectedLog.action}</span>
                </div>
                <div>
                  <small className="form-label">Status</small>
                  <span className="badge badge-emerald">{selectedLog.status}</span>
                </div>
              </div>

              {selectedLog.integrityHash && (
                <div style={{ marginBottom: '1rem', padding: '0.75rem', background: '#0f172a', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.08)' }}>
                  <div style={{ fontSize: '0.775rem', fontWeight: 600, color: '#38bdf8', marginBottom: '0.25rem', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                    <ShieldCheck size={14} color="#10b981" /> HMAC Audit Log Integrity Signature (SHA-256 Validated)
                  </div>
                  <div style={{ fontFamily: 'monospace', fontSize: '0.75rem', color: '#94a3b8', wordBreak: 'break-all' }}>
                    {selectedLog.integrityHash}
                  </div>
                </div>
              )}

              <div className="form-group">
                <small className="form-label">Full Audit Payload (JSON)</small>
                <textarea
                  className="form-textarea"
                  rows={10}
                  value={JSON.stringify(selectedLog, null, 2)}
                  readOnly
                  style={{ background: '#0b0f19', color: '#38bdf8' }}
                />
              </div>
            </div>
            <div className="modal-footer">
              <button className="btn btn-secondary" onClick={() => setSelectedLog(null)}>
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
