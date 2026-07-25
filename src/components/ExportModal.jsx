import React, { useState } from 'react';
import { Download, Lock, Key, FileCode, Check, AlertCircle } from 'lucide-react';

export function ExportModal({ cert, onClose }) {
  const [exportFormat, setExportFormat] = useState('pfx'); // 'pfx' | 'pem_cert' | 'pem_chain' | 'pem_full'
  const [pfxPassword, setPfxPassword] = useState('');
  const [confirmPfxPassword, setConfirmPfxPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const handleExport = async () => {
    setError(null);
    setLoading(true);

    try {
      if (exportFormat === 'pfx') {
        if (pfxPassword !== confirmPfxPassword) {
          throw new Error('Password and confirmation do not match.');
        }

        const res = await fetch(`/api/certificates/${cert.id}/export/pfx`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ password: pfxPassword })
        });

        if (!res.ok) {
          const errData = await res.json();
          throw new Error(errData.error || 'Failed to export PKCS#12 bundle.');
        }

        const blob = await res.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${cert.commonName || 'certificate'}.pfx`;
        document.body.appendChild(a);
        a.click();
        a.remove();
        window.URL.revokeObjectURL(url);
        onClose();
      } else {
        // PEM export
        let includeChain = exportFormat === 'pem_chain' || exportFormat === 'pem_full';
        let includeKey = exportFormat === 'pem_full';

        const url = `/api/certificates/${cert.id}/export/pem?includeChain=${includeChain}&includeKey=${includeKey}`;
        window.open(url, '_blank');
        onClose();
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="modal-overlay">
      <div className="modal-card" style={{ maxWidth: '600px' }}>
        <div className="modal-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Download style={{ color: 'var(--color-blue)' }} size={20} />
            <h3 style={{ fontFamily: 'var(--font-heading)', fontWeight: 700 }}>
              Export Certificate — {cert.commonName}
            </h3>
          </div>
          <button className="btn btn-secondary" style={{ padding: '0.2rem 0.5rem' }} onClick={onClose}>
            ✕
          </button>
        </div>

        <div className="modal-body">
          {error && (
            <div className="alert alert-danger">
              <AlertCircle size={16} />
              <div>{error}</div>
            </div>
          )}

          <div className="form-group">
            <label className="form-label">Export Format & Container</label>
            <div className="grid-2">
              <div
                onClick={() => setExportFormat('pfx')}
                style={{
                  padding: '1rem',
                  borderRadius: '8px',
                  border: exportFormat === 'pfx' ? '2px solid var(--color-blue)' : '1px solid var(--border-accent)',
                  background: exportFormat === 'pfx' ? '#eff6ff' : '#ffffff',
                  cursor: 'pointer'
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', marginBottom: '0.35rem' }}>
                  <Lock size={16} style={{ color: 'var(--color-blue)' }} />
                  <strong style={{ fontSize: '0.9rem' }}>PKCS#12 (.pfx / .p12)</strong>
                </div>
                <small style={{ color: 'var(--text-muted)', display: 'block', fontSize: '0.75rem' }}>
                  Encrypted bundle (Cert + Private Key + CA Chain). Supports password protection.
                </small>
              </div>

              <div
                onClick={() => setExportFormat('pem_full')}
                style={{
                  padding: '1rem',
                  borderRadius: '8px',
                  border: exportFormat === 'pem_full' ? '2px solid var(--color-blue)' : '1px solid var(--border-accent)',
                  background: exportFormat === 'pem_full' ? '#eff6ff' : '#ffffff',
                  cursor: 'pointer'
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', marginBottom: '0.35rem' }}>
                  <FileCode size={16} style={{ color: 'var(--color-indigo)' }} />
                  <strong style={{ fontSize: '0.9rem' }}>PEM Bundle (.pem)</strong>
                </div>
                <small style={{ color: 'var(--text-muted)', display: 'block', fontSize: '0.75rem' }}>
                  Text-encoded certificate, chain, and unencrypted key block.
                </small>
              </div>
            </div>
          </div>

          {exportFormat === 'pfx' && (
            <div style={{ background: '#f8fafc', padding: '1.25rem', borderRadius: '8px', border: '1px solid var(--border-subtle)', marginTop: '1rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', marginBottom: '0.85rem' }}>
                <Lock size={15} style={{ color: 'var(--color-blue)' }} />
                <strong style={{ fontSize: '0.875rem' }}>Optional Password Protection</strong>
              </div>
              <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '1rem' }}>
                Leave password empty for unencrypted PFX export, or enter a password to protect the private key payload.
              </p>

              <div className="form-group">
                <label className="form-label">Export Password (Optional)</label>
                <input
                  type="password"
                  className="form-input"
                  placeholder="Enter optional export password"
                  value={pfxPassword}
                  onChange={(e) => setPfxPassword(e.target.value)}
                />
              </div>

              {pfxPassword.length > 0 && (
                <div className="form-group">
                  <label className="form-label">Confirm Export Password</label>
                  <input
                    type="password"
                    className="form-input"
                    placeholder="Confirm export password"
                    value={confirmPfxPassword}
                    onChange={(e) => setConfirmPfxPassword(e.target.value)}
                  />
                </div>
              )}
            </div>
          )}
        </div>

        <div className="modal-footer">
          <button className="btn btn-secondary" onClick={onClose}>
            Cancel
          </button>
          <button className="btn btn-primary" onClick={handleExport} disabled={loading}>
            {loading ? 'Exporting...' : 'Download Export'} <Download size={14} />
          </button>
        </div>
      </div>
    </div>
  );
}
