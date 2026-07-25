import React, { useState } from 'react';
import { Terminal, Code, Copy, Play, Check, Send } from 'lucide-react';

export function ApiExplorer() {
  const [activeEndpoint, setActiveEndpoint] = useState('/api/setup/status');
  const [responseOutput, setResponseOutput] = useState('');
  const [loading, setLoading] = useState(false);

  const endpoints = [
    {
      method: 'GET',
      path: '/api/setup/status',
      description: 'Fetch CA initialization status, type, fingerprint, and certificate stats.'
    },
    {
      method: 'GET',
      path: '/api/certificates',
      description: 'Search and filter certificates by Common Name, SAN, serial, status, profile, or algorithm.'
    },
    {
      method: 'POST',
      path: '/api/certificates/issue',
      description: 'Issue certificate with automatic OPA policy compliance evaluation.',
      samplePayload: {
        commonName: 'api.internal.domain.com',
        certType: 'web_server',
        profile: 'standard',
        validityDays: 365,
        algorithm: 'RSA_2048',
        sans: ['api.internal.domain.com', '10.0.1.20'],
        masterPassphrase: 'YOUR_MASTER_PASSPHRASE'
      }
    },
    {
      method: 'POST',
      path: '/api/certificates/revoke',
      description: 'Revoke certificate with RFC 5280 reason code.',
      samplePayload: {
        certId: 'cert-1721900000',
        reasonCode: 1,
        revocationDetails: 'Key compromise suspected',
        masterPassphrase: 'YOUR_MASTER_PASSPHRASE'
      }
    },
    {
      method: 'POST',
      path: '/api/certificates/:id/export/pfx',
      description: 'Export password-protected PKCS#12 (.pfx / .p12) bundle.',
      samplePayload: {
        password: 'ExportSecretPassword123!'
      }
    },
    {
      method: 'GET',
      path: '/api/policies',
      description: 'Retrieve active OPA Rego governance rules.'
    },
    {
      method: 'GET',
      path: '/api/audit-logs',
      description: 'Search compliance audit trail records.'
    },
    {
      method: 'GET',
      path: '/api/crl',
      description: 'Fetch Certificate Revocation List (CRL).'
    },
    {
      method: 'GET',
      path: '/api/ca/chain',
      description: 'Download CA certificate chain PEM bundle.'
    }
  ];

  const handleTestApi = async (ep) => {
    setLoading(true);
    setResponseOutput('Executing API call...');

    try {
      let res;
      if (ep.method === 'GET') {
        res = await fetch(ep.path);
      } else {
        res = await fetch(ep.path, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(ep.samplePayload || {})
        });
      }
      const contentType = res.headers.get('content-type');
      if (contentType && contentType.includes('application/json')) {
        const json = await res.json();
        setResponseOutput(JSON.stringify(json, null, 2));
      } else {
        const text = await res.text();
        setResponseOutput(text.substring(0, 1000));
      }
    } catch (err) {
      setResponseOutput(`Error: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  const selectedEp = endpoints.find(e => e.path === activeEndpoint) || endpoints[0];

  return (
    <div>
      <div className="panel">
        <div className="panel-header">
          <div>
            <h2 className="panel-title">
              <Terminal style={{ color: 'var(--color-blue)' }} size={22} />
              REST API Exposure & Documentation
            </h2>
            <p className="panel-description">
              Programmatic REST endpoints for certificate issuance, CSR processing, revocation, OPA policy query, and CRL distribution.
            </p>
          </div>
        </div>

        <div className="grid-2">
          {/* Endpoint List */}
          <div>
            <label className="form-label" style={{ marginBottom: '0.5rem', display: 'block' }}>
              Available API Endpoints
            </label>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
              {endpoints.map((ep) => (
                <div
                  key={ep.path}
                  onClick={() => {
                    setActiveEndpoint(ep.path);
                    setResponseOutput('');
                  }}
                  style={{
                    padding: '0.85rem',
                    borderRadius: '6px',
                    border: activeEndpoint === ep.path ? '2px solid var(--color-blue)' : '1px solid var(--border-accent)',
                    background: activeEndpoint === ep.path ? '#eff6ff' : '#ffffff',
                    cursor: 'pointer',
                    display: 'flex',
                    justify: 'space-between',
                    alignItems: 'center'
                  }}
                >
                  <div>
                    <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                      <span className={`badge ${ep.method === 'GET' ? 'badge-emerald' : 'badge-indigo'}`}>
                        {ep.method}
                      </span>
                      <code className="code-inline" style={{ fontSize: '0.825rem' }}>
                        {ep.path}
                      </code>
                    </div>
                    <small style={{ color: 'var(--text-muted)', display: 'block', marginTop: '0.25rem' }}>
                      {ep.description}
                    </small>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Interactive Tester Panel */}
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
              <label className="form-label">Endpoint Tester & Curl Generator</label>
              <button
                className="btn btn-emerald"
                style={{ padding: '0.3rem 0.75rem', fontSize: '0.775rem' }}
                onClick={() => handleTestApi(selectedEp)}
                disabled={loading}
              >
                <Play size={13} /> {loading ? 'Testing...' : 'Execute Request'}
              </button>
            </div>

            <div className="form-group">
              <label className="form-label">Equivalent cURL Command</label>
              <div className="code-block" style={{ fontSize: '0.75rem', padding: '0.75rem' }}>
                {selectedEp.method === 'GET'
                  ? `curl -X GET http://localhost:3001${selectedEp.path}`
                  : `curl -X POST http://localhost:3001${selectedEp.path} \\\n  -H "Content-Type: application/json" \\\n  -d '${JSON.stringify(selectedEp.samplePayload || {}, null, 2)}'`}
              </div>
            </div>

            <div className="form-group">
              <label className="form-label">API Response Payload</label>
              <textarea
                className="form-textarea"
                rows={12}
                style={{ background: '#0b0f19', color: '#38bdf8', fontFamily: 'var(--font-mono)', fontSize: '0.775rem' }}
                value={responseOutput || '// Response body will appear here after execution...'}
                readOnly
              />
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
