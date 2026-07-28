import React, { useState } from 'react';
import { Upload, X, CheckCircle, AlertTriangle, RefreshCw, FileText } from 'lucide-react';

export function CertImportModal({ isOpen, onClose, onImportSuccess }) {
  const [certPem, setCertPem] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [successMsg, setSuccessMsg] = useState(null);

  if (!isOpen) return null;

  const handleImport = async (e) => {
    e.preventDefault();
    setError(null);
    setSuccessMsg(null);

    if (!certPem || !certPem.includes('CERTIFICATE')) {
      setError('Please provide a valid PEM-encoded X.509 certificate.');
      return;
    }

    setLoading(true);

    try {
      const res = await fetch('/api/certificates/import', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ certPem })
      });

      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Import failed.');

      setSuccessMsg(`Certificate '${data.certificate.commonName}' imported successfully into unified inventory.`);
      setCertPem('');
      if (onImportSuccess) onImportSuccess(data.certificate);
      setTimeout(() => {
        setSuccessMsg(null);
        onClose();
      }, 2000);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleFileUpload = (e) => {
    const file = e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (event) => {
      setCertPem(event.target.result);
    };
    reader.readAsText(file);
  };

  return (
    <div className="modal-overlay">
      <div className="modal-content card" style={{ maxWidth: '600px', width: '90%' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem' }}>
          <h3 style={{ fontSize: '1.1rem', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Upload className="icon-blue" size={20} /> Import External Certificate
          </h3>
          <button className="btn btn-secondary" style={{ padding: '0.25rem 0.5rem' }} onClick={onClose}>
            <X size={16} />
          </button>
        </div>

        <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)', marginBottom: '1rem' }}>
          Import existing external X.509 certificates (.pem / .crt) for central discovery, trust chain inspection, and expiration monitoring.
        </p>

        {error && (
          <div className="alert alert-danger" style={{ marginBottom: '1rem', fontSize: '0.85rem' }}>
            <AlertTriangle size={16} /> {error}
          </div>
        )}

        {successMsg && (
          <div className="alert alert-emerald" style={{ marginBottom: '1rem', fontSize: '0.85rem' }}>
            <CheckCircle size={16} /> {successMsg}
          </div>
        )}

        <form onSubmit={handleImport}>
          <div style={{ marginBottom: '1rem' }}>
            <label className="form-label" style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span>X.509 Certificate PEM</span>
              <label style={{ cursor: 'pointer', color: 'var(--color-blue)', fontSize: '0.8rem', display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                <FileText size={13} /> Load from File
                <input type="file" accept=".pem,.crt,.cer" onChange={handleFileUpload} style={{ display: 'none' }} />
              </label>
            </label>
            <textarea
              className="form-input"
              rows={8}
              placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----"
              value={certPem}
              onChange={e => setCertPem(e.target.value)}
              style={{ fontFamily: 'monospace', fontSize: '0.8rem' }}
              disabled={loading}
            />
          </div>

          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem' }}>
            <button type="button" className="btn btn-secondary" onClick={onClose} disabled={loading}>
              Cancel
            </button>
            <button type="submit" className="btn btn-emerald" disabled={loading || !certPem}>
              {loading ? <RefreshCw size={15} className="spin" /> : <Upload size={15} />} Import Certificate
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
