import React, { useState } from 'react';
import { Layers, FileSpreadsheet, CheckCircle, AlertTriangle, RefreshCw, Upload, Download, Play } from 'lucide-react';

export function BulkIssuance({ onComplete }) {
  const [jsonInput, setJsonInput] = useState(JSON.stringify([
    { commonName: 'api-service-1.internal.domain', certType: 'web_server', validityDays: 90, algorithm: 'RSA_2048' },
    { commonName: 'db-cluster-node1.internal.domain', certType: 'mtls', validityDays: 180, algorithm: 'ECDSA_P256' },
    { commonName: 'k8s-ingress-gateway.internal.domain', certType: 'web_server', validityDays: 365, algorithm: 'RSA_2048' }
  ], null, 2));

  const [loading, setLoading] = useState(false);
  const [resultData, setResultData] = useState(null);
  const [error, setError] = useState(null);

  const handleBatchIssue = async () => {
    setError(null);
    setLoading(true);
    setResultData(null);

    try {
      const parsedItems = JSON.parse(jsonInput);
      if (!Array.isArray(parsedItems) || parsedItems.length === 0) {
        throw new Error('Input must be a valid non-empty JSON array of certificate requests.');
      }

      const res = await fetch('/api/certificates/bulk-issue', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ items: parsedItems })
      });

      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Bulk issuance failed.');

      setResultData(data);
      if (onComplete) onComplete();
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="container" style={{ paddingTop: '1.5rem', paddingBottom: '3rem' }}>
      <div style={{ marginBottom: '1.5rem' }}>
        <h2 style={{ fontFamily: 'var(--font-heading)', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
          <Layers className="icon-blue" size={26} /> Bulk Batch Certificate Generator
        </h2>
        <p style={{ fontSize: '0.875rem', color: 'var(--text-muted)' }}>
          High-Throughput Batch Issuance • OPA Policy Validation • Multi-workload Automation
        </p>
      </div>

      <div className="grid-cols-2" style={{ gap: '1.5rem' }}>
        {/* Left Column: JSON / CSV Input */}
        <div className="card">
          <h3 style={{ fontSize: '1.05rem', fontWeight: 600, marginBottom: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <FileSpreadsheet size={18} /> Batch Request Definition (JSON / CSV Array)
          </h3>

          <textarea
            className="form-input"
            rows={14}
            style={{ fontFamily: 'monospace', fontSize: '0.825rem', lineHeight: '1.4' }}
            value={jsonInput}
            onChange={e => setJsonInput(e.target.value)}
          />

          <div style={{ marginTop: '1rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <button className="btn btn-emerald" onClick={handleBatchIssue} disabled={loading}>
              {loading ? <RefreshCw size={16} className="spin" /> : <Play size={16} />} Execute Batch Issuance
            </button>
          </div>

          {error && (
            <div className="alert alert-danger" style={{ marginTop: '1rem', fontSize: '0.85rem' }}>
              <AlertTriangle size={16} /> {error}
            </div>
          )}
        </div>

        {/* Right Column: Execution Output */}
        <div className="card">
          <h3 style={{ fontSize: '1.05rem', fontWeight: 600, marginBottom: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <CheckCircle size={18} className="icon-emerald" /> Batch Execution Results
          </h3>

          {!resultData ? (
            <div style={{ padding: '3rem 1rem', textAlign: 'center', color: 'var(--text-muted)', fontSize: '0.875rem' }}>
              Click "Execute Batch Issuance" to process requests under OPA governance rules.
            </div>
          ) : (
            <div>
              <div style={{ display: 'flex', gap: '1rem', marginBottom: '1rem' }}>
                <span className="badge badge-emerald">Issued: {resultData.issuedCount}</span>
                <span className="badge badge-danger">Errors: {resultData.errorCount}</span>
              </div>

              <div style={{ maxHeight: '380px', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                {resultData.issuedCertificates.map(c => (
                  <div key={c.index} style={{ padding: '0.6rem 0.8rem', background: '#0f172a', borderRadius: '6px', fontSize: '0.8rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <div>
                      <strong>{c.commonName}</strong>
                      <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Serial: {c.certificate.serialNumber}</div>
                    </div>
                    <span className="badge badge-emerald">SUCCESS</span>
                  </div>
                ))}

                {resultData.errors.map(err => (
                  <div key={err.index} style={{ padding: '0.6rem 0.8rem', background: '#1c1917', border: '1px solid #7f1d1d', borderRadius: '6px', fontSize: '0.8rem' }}>
                    <strong>{err.commonName}</strong> — <span style={{ color: '#f87171' }}>{err.error}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
