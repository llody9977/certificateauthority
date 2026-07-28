import React, { useState } from 'react';
import { Bot, Send, Shield, CheckCircle, AlertTriangle, RefreshCw, Key, FileText, Layers, CornerDownLeft } from 'lucide-react';

export function AiAssistant({ caStatus, currentUser, onRefreshStatus }) {
  const [messages, setMessages] = useState([
    {
      id: 'welcome',
      sender: 'assistant',
      text: 'Hello! I am your AI Certificate Assistant powered by Model Context Protocol (MCP). How can I assist with your PKI lifecycle today?',
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      quickActions: [
        { label: '🚀 Issue web server cert for api.internal.domain (90 days)', prompt: 'Issue a web server certificate for api.internal.domain for 90 days using RSA_2048' },
        { label: '🔍 Check CA health & revocation status', prompt: 'Check CA health and parent CRL sync status' },
        { label: '🛡️ Evaluate OPA policy for RSA_2048 (365 days)', prompt: 'Evaluate OPA policy for RSA_2048 with 365 days validity for service.local' },
        { label: '📋 List active certificates', prompt: 'List active certificates in CA inventory' }
      ]
    }
  ]);

  const [inputPrompt, setInputPrompt] = useState('');
  const [loading, setLoading] = useState(false);

  const callMcpTool = async (method, name, args = {}) => {
    const res = await fetch('/api/mcp', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-User-Role': currentUser?.role || 'Admin',
        'X-User-Name': currentUser?.performedBy || 'admin'
      },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 'mcp-' + Date.now(),
        method,
        params: { name, arguments: args }
      })
    });
    const data = await res.json();
    if (data.error) throw new Error(data.error.message);
    return data.result;
  };

  const processUserPrompt = async (promptText) => {
    if (!promptText.trim()) return;

    const userMsg = {
      id: 'msg-' + Date.now(),
      sender: 'user',
      text: promptText,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    };

    setMessages(prev => [...prev, userMsg]);
    setInputPrompt('');
    setLoading(true);

    try {
      const lower = promptText.toLowerCase();
      let replyObj = null;

      if (lower.includes('issue') || lower.includes('create cert')) {
        // Parse CN and validity
        const cnMatch = promptText.match(/(?:for|name)\s+([a-zA-Z0-9.-]+)/i) || promptText.match(/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
        const cn = cnMatch ? cnMatch[1] : 'web.internal.domain';
        const daysMatch = promptText.match(/(\d+)\s*days/i);
        const days = daysMatch ? parseInt(daysMatch[1]) : 90;

        // First evaluate OPA
        const opaRes = await callMcpTool('tools/call', 'evaluate_opa_policy', {
          commonName: cn,
          certType: 'web_server',
          profile: 'standard',
          validityDays: days,
          algorithm: 'RSA_2048',
          sans: [cn]
        });

        const opaData = JSON.parse(opaRes.content[0].text);

        replyObj = {
          text: `I simulated your request against corporate OPA Policy Rules.`,
          opaResult: opaData,
          pendingAction: {
            toolName: 'issue_certificate',
            args: {
              commonName: cn,
              certType: 'web_server',
              profile: 'standard',
              validityDays: days,
              algorithm: 'RSA_2048',
              sans: [cn]
            }
          }
        };
      } else if (lower.includes('check ca') || lower.includes('health') || lower.includes('status')) {
        const caRes = await callMcpTool('tools/call', 'check_ca_status', { forceRefresh: true });
        const caData = JSON.parse(caRes.content[0].text);
        replyObj = {
          text: `Retrieved live CA Status & Revocation Sync via MCP:`,
          dataPayload: caData
        };
      } else if (lower.includes('evaluate') || lower.includes('policy') || lower.includes('opa')) {
        const opaRes = await callMcpTool('tools/call', 'evaluate_opa_policy', {
          commonName: 'service.local',
          certType: 'web_server',
          profile: 'standard',
          validityDays: 365,
          algorithm: 'RSA_2048',
          sans: ['service.local']
        });
        const opaData = JSON.parse(opaRes.content[0].text);
        replyObj = {
          text: `OPA Policy Simulation Result for RSA_2048 (365 days):`,
          opaResult: opaData
        };
      } else if (lower.includes('list') || lower.includes('active') || lower.includes('certificates')) {
        const listRes = await callMcpTool('tools/call', 'list_certificates', { status: 'ACTIVE' });
        const listData = JSON.parse(listRes.content[0].text);
        replyObj = {
          text: `Found ${listData.count} active certificates in inventory:`,
          certList: listData.certificates
        };
      } else {
        // Fallback MCP Tool Manifest List
        const manifest = await callMcpTool('tools/list', '');
        replyObj = {
          text: `I understand PKI intent queries. You can ask me to issue certificates, check revocation, evaluate OPA policies, or list active inventory. Here are my MCP tools:`,
          mcpTools: manifest.tools
        };
      }

      setMessages(prev => [
        ...prev,
        {
          id: 'asst-' + Date.now(),
          sender: 'assistant',
          ...replyObj,
          timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
        }
      ]);
    } catch (err) {
      setMessages(prev => [
        ...prev,
        {
          id: 'err-' + Date.now(),
          sender: 'assistant',
          error: err.message,
          timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
        }
      ]);
    } finally {
      setLoading(false);
    }
  };

  const handleConfirmAction = async (msgId, actionObj) => {
    setLoading(true);
    try {
      const issueRes = await callMcpTool('tools/call', actionObj.toolName, actionObj.args);
      const resData = JSON.parse(issueRes.content[0].text);

      setMessages(prev =>
        prev.map(m => (m.id === msgId ? { ...m, pendingAction: null, executedResult: resData } : m))
      );

      if (onRefreshStatus) onRefreshStatus();
    } catch (err) {
      alert(`Action Failed: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="container" style={{ paddingTop: '1.5rem', paddingBottom: '3rem' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem' }}>
        <div>
          <h2 style={{ fontFamily: 'var(--font-heading)', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
            <Bot className="icon-emerald" size={26} /> AI Certificate Assistant Studio
          </h2>
          <p style={{ fontSize: '0.875rem', color: 'var(--text-muted)' }}>
            Model Context Protocol (MCP) Interface • Natural Language PKI Management & OPA Policy Guard
          </p>
        </div>

        <div style={{ display: 'flex', gap: '0.5rem' }}>
          <span className="badge badge-emerald">
            <Shield size={12} /> MCP JSON-RPC Server Active
          </span>
          <span className="badge badge-blue">
            <Key size={12} /> User Role: {currentUser?.role || 'Admin'}
          </span>
        </div>
      </div>

      <div className="card" style={{ display: 'flex', flexDirection: 'column', height: '640px', padding: 0, overflow: 'hidden' }}>
        {/* Chat Messages Log */}
        <div style={{ flex: 1, padding: '1.25rem', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '1.25rem', background: '#0b0f19' }}>
          {messages.map(msg => (
            <div
              key={msg.id}
              style={{
                display: 'flex',
                flexDirection: 'column',
                alignItems: msg.sender === 'user' ? 'flex-end' : 'flex-start'
              }}
            >
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '0.25rem' }}>
                {msg.sender === 'user' ? 'You' : 'AI Assistant'} • {msg.timestamp}
              </div>

              <div
                style={{
                  maxWidth: '82%',
                  padding: '1rem 1.25rem',
                  borderRadius: '12px',
                  background: msg.sender === 'user' ? 'var(--color-blue)' : '#151c2c',
                  color: '#fff',
                  border: msg.sender === 'user' ? 'none' : '1px solid rgba(255,255,255,0.08)',
                  boxShadow: '0 4px 12px rgba(0,0,0,0.2)'
                }}
              >
                {msg.text && <p style={{ fontSize: '0.9rem', lineHeight: '1.5', margin: 0 }}>{msg.text}</p>}

                {msg.error && (
                  <div className="alert alert-danger" style={{ marginTop: '0.5rem', fontSize: '0.825rem' }}>
                    <AlertTriangle size={16} />
                    <div>{msg.error}</div>
                  </div>
                )}

                {/* Quick Action Buttons */}
                {msg.quickActions && (
                  <div style={{ marginTop: '1rem', display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
                    {msg.quickActions.map((qa, idx) => (
                      <button
                        key={idx}
                        className="btn btn-secondary"
                        style={{ textAlign: 'left', fontSize: '0.8rem', padding: '0.4rem 0.75rem', background: '#1e293b' }}
                        onClick={() => processUserPrompt(qa.prompt)}
                      >
                        {qa.label}
                      </button>
                    ))}
                  </div>
                )}

                {/* OPA Policy Result Card */}
                {msg.opaResult && (
                  <div style={{ marginTop: '0.75rem', padding: '0.75rem', background: '#0f172a', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.1)' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.35rem' }}>
                      <Shield size={16} color={msg.opaResult.allowed ? '#10b981' : '#f59e0b'} />
                      <strong style={{ fontSize: '0.85rem' }}>
                        OPA Policy Evaluation: {msg.opaResult.allowed ? 'ALLOWED ✅' : 'DENIED ❌'}
                      </strong>
                    </div>
                    {msg.opaResult.violations && msg.opaResult.violations.length > 0 && (
                      <ul style={{ fontSize: '0.78rem', color: '#f87171', margin: 0, paddingLeft: '1.25rem' }}>
                        {msg.opaResult.violations.map((v, i) => <li key={i}>{v}</li>)}
                      </ul>
                    )}
                  </div>
                )}

                {/* Pending Confirmation Action Button */}
                {msg.pendingAction && (
                  <div style={{ marginTop: '0.85rem', textAlign: 'right' }}>
                    <button
                      className="btn btn-emerald"
                      style={{ fontSize: '0.825rem', padding: '0.4rem 0.85rem' }}
                      onClick={() => handleConfirmAction(msg.id, msg.pendingAction)}
                      disabled={loading}
                    >
                      <CheckCircle size={14} /> Confirm & Execute via MCP Server
                    </button>
                  </div>
                )}

                {/* Executed Result Card */}
                {msg.executedResult && (
                  <div className="alert alert-emerald" style={{ marginTop: '0.75rem', fontSize: '0.825rem' }}>
                    <CheckCircle size={18} />
                    <div>
                      <strong>Certificate Issued Successfully via MCP!</strong>
                      <div style={{ fontSize: '0.775rem', marginTop: '0.25rem' }}>
                        CN: {msg.executedResult.commonName} | Serial: {msg.executedResult.serialNumber}
                      </div>
                    </div>
                  </div>
                )}

                {/* Data Payload Card */}
                {msg.dataPayload && (
                  <pre style={{ marginTop: '0.75rem', padding: '0.75rem', background: '#090d16', borderRadius: '6px', fontSize: '0.75rem', color: '#38bdf8', overflowX: 'auto' }}>
                    {JSON.stringify(msg.dataPayload, null, 2)}
                  </pre>
                )}

                {/* Cert List Preview */}
                {msg.certList && (
                  <div style={{ marginTop: '0.75rem', display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
                    {msg.certList.map(c => (
                      <div key={c.id} style={{ fontSize: '0.78rem', padding: '0.4rem 0.6rem', background: '#0f172a', borderRadius: '6px', display: 'flex', justifyContent: 'space-between' }}>
                        <span><strong>{c.commonName}</strong> ({c.certType})</span>
                        <span style={{ color: 'var(--color-emerald)' }}>{c.status}</span>
                      </div>
                    ))}
                  </div>
                )}

                {/* MCP Tools Manifest Preview */}
                {msg.mcpTools && (
                  <div style={{ marginTop: '0.75rem', display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
                    {msg.mcpTools.map(t => (
                      <div key={t.name} style={{ fontSize: '0.78rem', padding: '0.4rem 0.6rem', background: '#0f172a', borderRadius: '6px' }}>
                        <code style={{ color: '#38bdf8' }}>{t.name}</code> — {t.description}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>

        {/* Input Bar */}
        <form
          onSubmit={e => {
            e.preventDefault();
            processUserPrompt(inputPrompt);
          }}
          style={{ padding: '0.85rem 1.25rem', background: '#111827', borderTop: '1px solid rgba(255,255,255,0.08)', display: 'flex', gap: '0.75rem' }}
        >
          <input
            type="text"
            className="form-input"
            placeholder="Ask AI Assistant (e.g. Issue web server cert for api.internal.domain for 90 days)..."
            value={inputPrompt}
            onChange={e => setInputPrompt(e.target.value)}
            disabled={loading}
            style={{ background: '#0b0f19' }}
          />
          <button type="submit" className="btn btn-emerald" disabled={loading || !inputPrompt.trim()}>
            {loading ? <RefreshCw size={16} className="spin" /> : <Send size={16} />}
          </button>
        </form>
      </div>
    </div>
  );
}
