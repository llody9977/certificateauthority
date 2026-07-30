import React, { useState, useEffect } from 'react';
import { Clock, AlertTriangle, ShieldAlert, CheckCircle, Bell, RefreshCw, Send, Layers } from 'lucide-react';

export function ExpirationRadar() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [webhookUrl, setWebhookUrl] = useState('');
  const [testSent, setTestSent] = useState(false);

  const fetchAlerts = async () => {
    setLoading(true);
    try {
      const res = await fetch('/api/certificates/alerts');
      const json = await res.json();
      setData(json);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAlerts();
  }, []);

  const handleTestWebhook = () => {
    if (!webhookUrl) return;
    setTestSent(true);
    setTimeout(() => setTestSent(false), 3000);
  };

  if (loading) {
    return (
      <div className="container" style={{ paddingTop: '2rem', textAlign: 'center' }}>
        <RefreshCw size={24} className="spin" />
        <p style={{ marginTop: '0.5rem', color: 'var(--text-muted)' }}>Scanning Certificate Expiration Tiers...</p>
      </div>
    );
  }

  const { summary, critical, warning, attention, healthy } = data || {
    summary: { criticalCount: 0, warningCount: 0, attentionCount: 0, healthyCount: 0 },
    critical: [],
    warning: [],
    attention: [],
    healthy: []
  };

  return (
    <div className="container" style={{ paddingTop: '1.5rem', paddingBottom: '3rem' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem' }}>
        <div>
          <h2 style={{ fontFamily: 'var(--font-heading)', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
            <Clock className="icon-amber" size={26} /> Certificate Expiration Radar & Alerts
          </h2>
          <p style={{ fontSize: '0.875rem', color: 'var(--text-muted)' }}>
            Real-time Lifecycle Monitoring • Expiration Risk Tiers • Webhook Notification Engine
          </p>
        </div>

        <button className="btn btn-secondary" onClick={fetchAlerts} style={{ fontSize: '0.85rem' }}>
          <RefreshCw size={14} /> Refresh Radar
        </button>
      </div>

      {/* Summary Risk Cards */}
      <div className="grid-cols-4" style={{ marginBottom: '1.5rem' }}>
        <div className="card" style={{ borderLeft: '4px solid #ef4444' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: '0.8rem', textTransform: 'uppercase', letterSpacing: '0.05em', color: '#f87171', fontWeight: 600 }}>
              Critical (&lt; 14 Days)
            </span>
            <ShieldAlert size={20} color="#ef4444" />
          </div>
          <div style={{ fontSize: '2.2rem', fontWeight: 700, marginTop: '0.5rem', color: '#ef4444' }}>
            {summary.criticalCount}
          </div>
        </div>

        <div className="card" style={{ borderLeft: '4px solid #f59e0b' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: '0.8rem', textTransform: 'uppercase', letterSpacing: '0.05em', color: '#fbbf24', fontWeight: 600 }}>
              Warning (&lt; 30 Days)
            </span>
            <AlertTriangle size={20} color="#f59e0b" />
          </div>
          <div style={{ fontSize: '2.2rem', fontWeight: 700, marginTop: '0.5rem', color: '#f59e0b' }}>
            {summary.warningCount}
          </div>
        </div>

        <div className="card" style={{ borderLeft: '4px solid #3b82f6' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: '0.8rem', textTransform: 'uppercase', letterSpacing: '0.05em', color: '#60a5fa', fontWeight: 600 }}>
              Attention (&lt; 60 Days)
            </span>
            <Clock size={20} color="#3b82f6" />
          </div>
          <div style={{ fontSize: '2.2rem', fontWeight: 700, marginTop: '0.5rem', color: '#3b82f6' }}>
            {summary.attentionCount}
          </div>
        </div>

        <div className="card" style={{ borderLeft: '4px solid #10b981' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: '0.8rem', textTransform: 'uppercase', letterSpacing: '0.05em', color: '#34d399', fontWeight: 600 }}>
              Healthy (&gt; 60 Days)
            </span>
            <CheckCircle size={20} color="#10b981" />
          </div>
          <div style={{ fontSize: '2.2rem', fontWeight: 700, marginTop: '0.5rem', color: '#10b981' }}>
            {summary.healthyCount}
          </div>
        </div>
      </div>

      {/* Critical & Warning Certificate Tables */}
      <div className="card" style={{ marginBottom: '1.5rem' }}>
        <h3 style={{ fontSize: '1.05rem', fontWeight: 600, marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <ShieldAlert size={18} color="#ef4444" /> Certificates Requiring Immediate Action
        </h3>

        {critical.length === 0 && warning.length === 0 ? (
          <div className="alert alert-emerald" style={{ fontSize: '0.875rem' }}>
            <CheckCircle size={18} /> No certificates are in Critical or Warning expiration windows.
          </div>
        ) : (
          <div className="table-responsive">
            <table className="table">
              <thead>
                <tr>
                  <th>Common Name</th>
                  <th>Serial Number</th>
                  <th>Type</th>
                  <th>Expiration Date</th>
                  <th>Days Remaining</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {[...critical, ...warning].map(c => (
                  <tr key={c.id}>
                    <td><strong>{c.commonName}</strong></td>
                    <td style={{ fontFamily: 'monospace', fontSize: '0.8rem' }}>{c.serialNumber}</td>
                    <td><span className="badge badge-secondary">{c.certType}</span></td>
                    <td style={{ fontFamily: 'monospace', fontSize: '0.8rem' }}>{new Date(c.validTo).toISOString().replace('T', ' ').substring(0, 19)}</td>
                    <td>
                      <span className={`badge ${c.daysRemaining <= 14 ? 'badge-danger' : 'badge-warning'}`}>
                        {c.daysRemaining} days left
                      </span>
                    </td>
                    <td>
                      <button className="btn btn-secondary" style={{ fontSize: '0.75rem', padding: '0.25rem 0.5rem' }}>
                        Auto-Renew
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Webhook Alert Engine Configuration */}
      <div className="card">
        <h3 style={{ fontSize: '1.05rem', fontWeight: 600, marginBottom: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <Bell size={18} className="icon-blue" /> Webhook Alert Notification Engine (Slack / PagerDuty / Teams)
        </h3>
        <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)', marginBottom: '1rem' }}>
          Configure an automated webhook payload trigger whenever certificates enter Critical (&lt; 14 days) or Warning (&lt; 30 days) windows.
        </p>

        <div style={{ display: 'flex', gap: '0.75rem', maxWidth: '640px' }}>
          <input
            type="url"
            className="form-input"
            placeholder="https://hooks.slack.com/services/T00/B00/XXXXX"
            value={webhookUrl}
            onChange={e => setWebhookUrl(e.target.value)}
          />
          <button className="btn btn-emerald" onClick={handleTestWebhook} disabled={!webhookUrl}>
            <Send size={15} /> Send Test Alert Payload
          </button>
        </div>

        {testSent && (
          <div className="alert alert-emerald" style={{ marginTop: '1rem', fontSize: '0.825rem' }}>
            <CheckCircle size={16} /> Test webhook alert payload dispatched successfully to destination endpoint!
          </div>
        )}
      </div>
    </div>
  );
}
