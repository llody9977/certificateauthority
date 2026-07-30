import express from 'express';
import cors from 'cors';
import path from 'path';
import fs from 'fs';
import crypto from 'crypto';
import { getDb, saveDb, addAuditLog, generateRegoFromForm } from './db.js';
import {
  initializeRootCa,
  generateIntermediateCsr,
  completeIntermediateCaSetup,
  createCsr,
  issueCertificate,
  issueSshCertificate,
  revokeCertificate,
  generateCrl,
  exportPkcs12,
  computeFingerprint,
  setCaSessionPassphrase,
  getCaSessionPassphrase,
  clearCaSessionPassphrase,
  decryptPrivateKey,
  getRevocationStatusWithTtlCache,
  syncParentCrlAndCheckRevocation,
  generateUniqueSerialNumber,
  replaceSubCaCertificate,
  resetCaConfiguration,
  updateParentCrlUrl,
  updateCrlDistributionPoint,
  checkAndUpdateExpiredCertificates
} from './pki.js';
import { evaluatePolicy } from './opa.js';

import { handleMcpRequest, MCP_TOOLS_MANIFEST } from './mcp.js';

const app = express();
const PORT = process.env.PORT || 8088;

app.use(cors());
app.use(express.json({ limit: '10mb' }));

// Universal API Request Audit Logging Middleware
app.use('/api', (req, res, next) => {
  if (req.path === '/audit-logs') return next();

  res.on('finish', () => {
    const context = getContextFromReq(req);
    const statusText = res.statusCode < 400 ? 'SUCCESS' : 'FAILED';
    const actionName = `API_${req.method}_${req.path.replace(/^\/api\//, '').replace(/\//g, '_').toUpperCase()}`;

    addAuditLog(actionName, context.performedBy, req.path, statusText, {
      method: req.method,
      statusCode: res.statusCode,
      query: req.query
    }, context);
  });

  next();
});

// RBAC Context & Permission Middleware
export function getContextFromReq(req) {
  const role = req.headers['x-user-role'] || 'Guest';
  const performedBy = req.headers['x-user-name'] || 'anonymous';
  const ipAddress = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';
  const userAgent = req.headers['user-agent'] || 'Browser/Client';

  return { role, performedBy, ipAddress, userAgent };
}

export function enforceRole(allowedRoles = []) {
  return (req, res, next) => {
    const { role } = getContextFromReq(req);

    if (allowedRoles.length > 0 && !allowedRoles.includes(role)) {
      addAuditLog('ACCESS_DENIED', req.headers['x-user-name'] || 'user', req.path, 'FORBIDDEN', {
        requiredRoles: allowedRoles,
        userRole: role
      }, getContextFromReq(req));

      return res.status(403).json({
        error: `Forbidden. Role '${role}' lacks permission for this operation. Required: ${allowedRoles.join(', ')}.`
      });
    }

    next();
  };
}

// Current User & RBAC Identity API
app.get('/api/auth/current-user', (req, res) => {
  res.json(getContextFromReq(req));
});

// Model Context Protocol (MCP) Interface Endpoint
app.post('/api/mcp', async (req, res) => {
  try {
    const context = getContextFromReq(req);
    const result = await handleMcpRequest(req.body, context);
    res.json(result);
  } catch (err) {
    res.status(400).json({ jsonrpc: '2.0', id: req.body?.id || null, error: { code: -32603, message: err.message } });
  }
});

// 1. Health & Setup Status API
app.get('/api/setup/status', (req, res) => {
  const db = getDb();
  if (!db.config) {
    return res.json({ initialized: false });
  }

  const { caKeyEncrypted, ...safeConfig } = db.config;
  res.json({
    initialized: true,
    config: safeConfig,
    activeCertCount: db.certificates.filter(c => c.status === 'ACTIVE' && !c.chainRevoked).length,
    revokedCertCount: db.certificates.filter(c => c.status === 'REVOKED' || c.chainRevoked).length,
    sshCertCount: db.sshCertificates ? db.sshCertificates.length : 0,
    sessionUnlocked: Boolean(getCaSessionPassphrase())
  });
});

// 1b. Session Passphrase Unlock API
app.post('/api/session/unlock', (req, res) => {
  try {
    const { passphrase, durationMinutes } = req.body;
    const db = getDb();
    if (!db.config) return res.status(400).json({ error: 'CA is not initialized.' });

    // Validate passphrase
    decryptPrivateKey(db.config.caKeyEncrypted, passphrase);

    setCaSessionPassphrase(passphrase, durationMinutes || 15);
    addAuditLog('SESSION_UNLOCK', 'admin', 'ca_session', 'SUCCESS', { durationMinutes: durationMinutes || 15 });

    res.json({ success: true, message: 'CA Session unlocked for automated signing/revocation.' });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post('/api/session/lock', (req, res) => {
  clearCaSessionPassphrase();
  addAuditLog('SESSION_LOCK', 'admin', 'ca_session', 'SUCCESS');
  res.json({ success: true, message: 'CA Session locked.' });
});

// 2. Initialize Root CA
app.post('/api/setup/root', (req, res) => {
  try {
    const { caName, organization, organizationalUnit, country, state, locality, algorithm, validityYears, passphrase } = req.body;
    if (!caName || !passphrase) {
      return res.status(400).json({ error: 'CA Name and Master Passphrase are required.' });
    }

    const config = initializeRootCa({
      caName,
      organization: organization || 'Enterprise Trust CA',
      organizationalUnit: organizationalUnit || 'Security Division',
      country: country || 'US',
      state: state || 'California',
      locality: locality || 'San Francisco',
      algorithm: algorithm || 'RSA_2048',
      validityYears: validityYears || 10,
      passphrase
    });

    const { caKeyEncrypted, ...safeConfig } = config;
    res.json({ success: true, config: safeConfig });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 3. Setup Intermediate CA Step 1
app.post('/api/setup/intermediate-csr', (req, res) => {
  try {
    const { caName, organization, organizationalUnit, country, state, locality, algorithm } = req.body;
    const result = generateIntermediateCsr({
      caName,
      organization: organization || 'Enterprise Intermediate CA',
      organizationalUnit,
      country,
      state,
      locality,
      algorithm
    });
    res.json({ success: true, ...result });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 2. Root CA Initialization
app.post('/api/setup/root-init', enforceRole(['Admin']), (req, res) => {
  try {
    const config = initializeRootCa(req.body);
    const { caKeyEncrypted, ...safeConfig } = config;
    res.json({ success: true, config: safeConfig });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// 3. Intermediate CA Setup & Completion
app.post('/api/setup/intermediate-csr', enforceRole(['Admin', 'Issuer']), (req, res) => {
  try {
    const result = generateIntermediateCsr(req.body);
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post('/api/setup/intermediate-complete', enforceRole(['Admin']), (req, res) => {
  try {
    const config = completeIntermediateCaSetup(req.body);
    const { caKeyEncrypted, ...safeConfig } = config;
    res.json({ success: true, config: safeConfig });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// 4b. Replace Sub-CA Certificate
app.post('/api/setup/replace-cert', enforceRole(['Admin']), (req, res) => {
  try {
    const { subCaCertPem, parentRootCertPem, subCaPrivateKeyPem, passphrase } = req.body;
    const config = replaceSubCaCertificate({ subCaCertPem, parentRootCertPem, subCaPrivateKeyPem, passphrase });
    const { caKeyEncrypted, ...safeConfig } = config;
    res.json({ success: true, config: safeConfig });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// 4c. Reset CA Configuration (Decommission & Re-initialize)
app.post('/api/setup/reset', enforceRole(['Admin']), (req, res) => {
  try {
    const { passphrase } = req.body;
    const result = resetCaConfiguration(passphrase);
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// 4d. Dynamic Parent CRL Endpoint URL Update
app.post('/api/setup/update-crl-url', (req, res) => {
  try {
    const { parentCrlUrl, passphrase } = req.body;
    if (!parentCrlUrl) {
      return res.status(400).json({ error: 'Parent CRL URL is required.' });
    }
    const config = updateParentCrlUrl(parentCrlUrl, passphrase);
    const { caKeyEncrypted, ...safeConfig } = config;
    res.json({ success: true, message: 'Parent CRL Endpoint URL updated successfully.', config: safeConfig });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// 4e. Dynamic Published CRL Distribution Point (CDP) URL Update
app.post('/api/setup/update-cdp', (req, res) => {
  try {
    const { crlDistributionPoint, passphrase } = req.body;
    if (!crlDistributionPoint) {
      return res.status(400).json({ error: 'CRL Distribution Point URL is required.' });
    }
    const config = updateCrlDistributionPoint(crlDistributionPoint, passphrase);
    const { caKeyEncrypted, ...safeConfig } = config;
    res.json({ success: true, message: 'Published CRL Distribution Point (CDP) URL updated successfully.', config: safeConfig });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// 5. Search & List Certificates
app.get('/api/certificates', async (req, res) => {
  checkAndUpdateExpiredCertificates();
  const db = getDb();

  // Sync Parent CRL if Intermediate CA
  await syncParentCrlAndCheckRevocation();

  const { query, status, certType, profile, algorithm, includeSelfAnchor } = req.query;

  let certs = db.certificates;

  // Filter out Root CA self-anchor unless explicitly requested
  if (includeSelfAnchor !== 'true') {
    certs = certs.filter(c => c.certType !== 'root_ca');
  }

  if (status) {
    const s = status.toUpperCase();
    certs = certs.filter(c => {
      const isExpired = new Date(c.validTo) < new Date();
      const currentStatus = isExpired ? 'EXPIRED' : c.status;
      return currentStatus === s;
    });
  }

  if (certType) certs = certs.filter(c => c.certType === certType);
  if (profile) certs = certs.filter(c => c.profile === profile);
  if (algorithm) certs = certs.filter(c => c.algorithm === algorithm);

  if (query) {
    const q = query.toLowerCase();
    certs = certs.filter(c => 
      (c.commonName && c.commonName.toLowerCase().includes(q)) ||
      (c.serialNumber && c.serialNumber.toLowerCase().includes(q)) ||
      (c.fingerprint && c.fingerprint.toLowerCase().includes(q)) ||
      (c.sans && c.sans.some(san => san.toLowerCase().includes(q)))
    );
  }

  const safeCerts = certs.map(c => {
    const { privateKeyPem, ...safe } = c;
    const isExpired = new Date(c.validTo) < new Date();
    const currentStatus = isExpired ? 'EXPIRED' : c.status;

    const newerCert = db.certificates.find(other => 
      other.id !== c.id &&
      other.commonName &&
      c.commonName &&
      other.commonName.toLowerCase() === c.commonName.toLowerCase() &&
      new Date(other.issuedAt || other.validFrom) > new Date(c.issuedAt || c.validFrom) &&
      other.status === 'ACTIVE'
    );

    let effStatus = currentStatus;
    if ((db.config && db.config.status === 'REVOKED') || c.chainRevoked) {
      effStatus = 'CHAIN_REVOKED';
    }

    return {
      ...safe,
      status: currentStatus,
      hasPrivateKey: Boolean(privateKeyPem),
      effectiveStatus: effStatus,
      isRenewed: Boolean(newerCert),
      renewedBySerial: newerCert ? newerCert.serialNumber : null
    };
  });

  const revCacheStats = getRevocationStatusWithTtlCache();

  res.json({
    certificates: safeCerts,
    total: safeCerts.length,
    revocationCacheStats: revCacheStats
  });
});

// 6. Get Certificate Trust Chain Inspector Detail
app.get('/api/certificates/:id/chain', (req, res) => {
  const db = getDb();
  const cert = db.certificates.find(c => c.id === req.params.id || c.serialNumber === req.params.id);

  if (!cert) {
    // Check if checking CA itself
    if (db.config && (db.config.serialNumber === req.params.id || db.config.caName === req.params.id)) {
      return res.json({
        chain: [
          {
            level: 'CA_AUTHORITY',
            commonName: db.config.caName,
            serialNumber: db.config.serialNumber,
            status: db.config.status || 'ACTIVE',
            fingerprint: db.config.fingerprint,
            type: db.config.type
          }
        ],
        validTrustChain: db.config.status !== 'REVOKED'
      });
    }
    return res.status(404).json({ error: 'Certificate not found' });
  }

  const chainNodes = [
    {
      level: 'END_ENTITY',
      commonName: cert.commonName,
      serialNumber: cert.serialNumber,
      status: cert.status,
      fingerprint: cert.fingerprint,
      certType: cert.certType
    },
    {
      level: 'ISSUING_CA',
      commonName: db.config.caName,
      serialNumber: db.config.serialNumber,
      status: db.config.status || 'ACTIVE',
      fingerprint: db.config.fingerprint,
      type: db.config.type
    }
  ];

  const validTrustChain = cert.status === 'ACTIVE' && db.config.status !== 'REVOKED' && !cert.chainRevoked;

  res.json({
    certificateId: cert.id,
    commonName: cert.commonName,
    chain: chainNodes,
    validTrustChain,
    chainRevoked: !validTrustChain
  });
});

// 7. Issue Certificate Endpoint (OPA Policy Protected & RBAC Guarded)
app.post('/api/certificates/issue', enforceRole(['Admin', 'Issuer', 'Requester']), async (req, res) => {
  try {
    const {
      commonName,
      organization,
      organizationalUnit,
      country,
      state,
      locality,
      emailAddress,
      certType,
      profile,
      validityDays,
      validityMinutes,
      algorithm,
      sans,
      csrPem,
      masterPassphrase
    } = req.body;

    const certRecord = await issueCertificate({
      commonName,
      organization,
      organizationalUnit,
      country,
      state,
      locality,
      emailAddress,
      certType,
      profile,
      validityDays,
      validityMinutes,
      algorithm,
      sans,
      csrPem,
      masterPassphrase
    });

    const { privateKeyPem, ...safe } = certRecord;
    res.json({ success: true, certificate: { ...safe, hasPrivateKey: Boolean(privateKeyPem) } });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// 8. Issue OpenSSH User/Host Certificate
app.post('/api/ssh/issue', (req, res) => {
  try {
    const { identity, certType, principals, publicSshKey, validityDays, algorithm, masterPassphrase } = req.body;

    const sshRecord = issueSshCertificate({
      identity,
      certType: certType || 'ssh_user',
      principals: principals || ['ubuntu'],
      publicSshKey,
      validityDays: validityDays || 30,
      algorithm: algorithm || 'ECDSA_P256',
      masterPassphrase
    });

    res.json({ success: true, sshCertificate: sshRecord });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// 9. ACME Directory Endpoint
app.get('/api/acme/directory', (req, res) => {
  res.json({
    newNonce: `${req.protocol}://${req.get('host')}/api/acme/new-nonce`,
    newAccount: `${req.protocol}://${req.get('host')}/api/acme/new-account`,
    newOrder: `${req.protocol}://${req.get('host')}/api/acme/new-order`,
    revokeCert: `${req.protocol}://${req.get('host')}/api/certificates/revoke`,
    keyChange: `${req.protocol}://${req.get('host')}/api/acme/key-change`,
    meta: {
      termsOfService: 'https://step.sm/terms',
      website: 'https://smallstep.com/docs/step-ca',
      caaIdentities: ['step-ca', 'stepca-enterprise'],
      externalAccountRequired: false
    }
  });
});

// 10. Revoke Certificate
app.post('/api/certificates/revoke', enforceRole(['Admin', 'Issuer']), (req, res) => {
  try {
    const { certId, reasonCode, revocationDetails, masterPassphrase } = req.body;
    if (!certId) {
      return res.status(400).json({ error: 'Certificate ID is required.' });
    }

    const updatedCert = revokeCertificate(certId, reasonCode, revocationDetails, masterPassphrase);
    res.json({ success: true, certificate: updatedCert });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// 11. Export Password-Protected PKCS#12 (.pfx / .p12)
app.post('/api/certificates/:id/export/pfx', (req, res) => {
  try {
    const { password } = req.body;
    const certId = req.params.id;

    const pfxBuffer = exportPkcs12(certId, password || '');

    res.setHeader('Content-Type', 'application/x-pkcs12');
    res.setHeader('Content-Disposition', `attachment; filename="${certId}.pfx"`);
    res.send(pfxBuffer);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// 12. Export PEM Certificate & Key
app.get('/api/certificates/:id/export/pem', (req, res) => {
  try {
    const db = getDb();
    const cert = db.certificates.find(c => c.id === req.params.id || c.serialNumber === req.params.id);

    if (!cert) return res.status(404).json({ error: 'Certificate not found' });

    let exportContent = cert.certPem;
    if (req.query.includeChain === 'true') exportContent += '\n' + (cert.chainPem || '');
    if (req.query.includeKey === 'true' && cert.privateKeyPem) exportContent += '\n' + cert.privateKeyPem;

    res.setHeader('Content-Type', 'application/x-pem-file');
    res.setHeader('Content-Disposition', `attachment; filename="${cert.commonName || 'certificate'}.pem"`);
    res.send(exportContent);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// 13. Create CSR
app.post('/api/csr/create', (req, res) => {
  try {
    const csrRecord = createCsr(req.body);
    res.json({ success: true, csr: csrRecord });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// 14. OPA Policy APIs
app.get('/api/policies', (req, res) => {
  const db = getDb();
  res.json({ policies: db.opaPolicies });
});

app.put('/api/policies/:id', (req, res) => {
  try {
    const db = getDb();
    const policyIndex = db.opaPolicies.findIndex(p => p.id === req.params.id);
    if (policyIndex === -1) return res.status(404).json({ error: 'Policy not found' });

    const { settings, enabled, name, description } = req.body;

    const updatedSettings = settings || db.opaPolicies[policyIndex].settings;
    const compiledRego = generateRegoFromForm(updatedSettings);

    db.opaPolicies[policyIndex] = {
      ...db.opaPolicies[policyIndex],
      settings: updatedSettings,
      rego: compiledRego,
      enabled: enabled !== undefined ? enabled : db.opaPolicies[policyIndex].enabled,
      name: name || db.opaPolicies[policyIndex].name,
      description: description || db.opaPolicies[policyIndex].description
    };

    saveDb(db);

    addAuditLog('UPDATE_OPA_POLICY', 'admin', db.opaPolicies[policyIndex].name, 'SUCCESS', {
      policyId: req.params.id,
      settings: updatedSettings
    });

    res.json({ success: true, policy: db.opaPolicies[policyIndex] });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// 15. Audit Log Search API
app.get('/api/audit-logs', (req, res) => {
  const db = getDb();
  const { query, action, status } = req.query;

  let logs = db.auditLogs;

  if (action) logs = logs.filter(l => l.action === action);
  if (status) logs = logs.filter(l => l.status === status);

  if (query) {
    const q = query.toLowerCase();
    logs = logs.filter(l =>
      l.action.toLowerCase().includes(q) ||
      l.actor.toLowerCase().includes(q) ||
      l.target.toLowerCase().includes(q) ||
      JSON.stringify(l.details).toLowerCase().includes(q)
    );
  }

  res.json({ auditLogs: logs, total: logs.length });
});

// 16. CRL Endpoint
app.get('/api/crl', (req, res) => {
  try {
    const crl = generateCrl();
    res.json(crl);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

import { handleEstCacerts, handleEstSimpleEnroll } from './est.js';

// 18. EST (Enrollment over Secure Transport - RFC 7030) Endpoints
app.get('/.well-known/est/cacerts', (req, res) => handleEstCacerts(req, res));
app.post('/.well-known/est/simpleenroll', express.text({ type: '*/*', limit: '5mb' }), (req, res) => {
  const context = getContextFromReq(req);
  handleEstSimpleEnroll(req, res, context);
});

// 19. External Certificate Import & Unified Discovery API
app.post('/api/certificates/import', enforceRole(['Admin', 'Issuer']), (req, res) => {
  try {
    const { certPem } = req.body;
    if (!certPem || typeof certPem !== 'string' || !certPem.includes('CERTIFICATE')) {
      return res.status(400).json({ error: 'Valid X.509 Certificate PEM string is required.' });
    }

    const forgeCert = pki.certificateFromPem(certPem);
    const cnAttr = forgeCert.subject.attributes.find(a => a.name === 'commonName' || a.shortName === 'CN');
    const commonName = cnAttr ? cnAttr.value : 'external-import';
    const fingerprint = computeFingerprint(certPem);
    const serialNumber = forgeCert.serialNumber;

    const db = getDb();
    if (db.certificates.some(c => c.fingerprint === fingerprint || c.serialNumber === serialNumber)) {
      return res.status(400).json({ error: 'Certificate already exists in inventory.' });
    }

    const importedRecord = {
      id: 'ext-' + Date.now() + '-' + crypto.randomUUID().split('-')[0],
      commonName,
      serialNumber,
      certPem,
      fingerprint,
      certType: 'external_imported',
      profile: 'external',
      validFrom: forgeCert.validity.notBefore.toISOString(),
      validTo: forgeCert.validity.notAfter.toISOString(),
      status: new Date() > forgeCert.validity.notAfter ? 'EXPIRED' : 'ACTIVE',
      importedAt: new Date().toISOString(),
      isExternal: true,
      hasPrivateKey: false
    };

    db.certificates.unshift(importedRecord);
    saveDb(db);

    addAuditLog('IMPORT_EXTERNAL_CERTIFICATE', getContextFromReq(req).performedBy, commonName, 'SUCCESS', {
      serialNumber,
      fingerprint
    }, getContextFromReq(req));

    res.json({ success: true, certificate: importedRecord });
  } catch (err) {
    res.status(400).json({ error: `Certificate Import Failed: ${err.message}` });
  }
});

// 20. Bulk CSV/JSON Batch Certificate Issuance API
app.post('/api/certificates/bulk-issue', enforceRole(['Admin', 'Issuer']), async (req, res) => {
  try {
    const { items, masterPassphrase } = req.body; // items: Array of { commonName, certType, validityDays, algorithm }
    if (!Array.isArray(items) || items.length === 0) {
      return res.status(400).json({ error: 'Array of certificate request items is required.' });
    }

    if (items.length > 100) {
      return res.status(400).json({ error: 'Bulk issuance batch size limit is 100 items per request.' });
    }

    const results = [];
    const errors = [];

    for (let i = 0; i < items.length; i++) {
      const item = items[i];
      try {
        const cert = await issueCertificate({
          commonName: item.commonName,
          certType: item.certType || 'web_server',
          profile: item.profile || 'standard',
          validityDays: parseInt(item.validityDays || 365),
          algorithm: item.algorithm || 'RSA_2048',
          sans: item.sans || [item.commonName],
          masterPassphrase
        });

        const { privateKeyPem, ...safe } = cert;
        results.push({ index: i, commonName: item.commonName, success: true, certificate: safe });
      } catch (err) {
        errors.push({ index: i, commonName: item.commonName, success: false, error: err.message });
      }
    }

    addAuditLog('BULK_ISSUE_CERTIFICATES', getContextFromReq(req).performedBy, `${results.length} Certs Issued`, 'SUCCESS', {
      requestedCount: items.length,
      successCount: results.length,
      errorCount: errors.length
    }, getContextFromReq(req));

    res.json({
      success: true,
      requestedCount: items.length,
      issuedCount: results.length,
      errorCount: errors.length,
      issuedCertificates: results,
      errors
    });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// 21. Certificate Expiration Radar & Webhook Alerts API
app.get('/api/certificates/alerts', (req, res) => {
  const db = getDb();
  const now = new Date();

  const activeCerts = db.certificates.filter(c => c.status === 'ACTIVE');

  const critical = []; // < 14 days
  const warning = [];  // < 30 days
  const attention = [];// < 60 days
  const healthy = [];  // > 60 days

  activeCerts.forEach(c => {
    const validTo = new Date(c.validTo);
    const diffDays = Math.ceil((validTo - now) / (1000 * 60 * 60 * 24));

    const item = {
      id: c.id,
      commonName: c.commonName,
      serialNumber: c.serialNumber,
      certType: c.certType,
      validTo: c.validTo,
      daysRemaining: diffDays
    };

    if (diffDays <= 14) critical.push(item);
    else if (diffDays <= 30) warning.push(item);
    else if (diffDays <= 60) attention.push(item);
    else healthy.push(item);
  });

  res.json({
    summary: {
      totalActive: activeCerts.length,
      criticalCount: critical.length,
      warningCount: warning.length,
      attentionCount: attention.length,
      healthyCount: healthy.length
    },
    critical,
    warning,
    attention,
    healthy
  });
});

// Serve frontend static build in production
const distPath = path.join(process.cwd(), 'dist');
if (fs.existsSync(distPath)) {
  app.use(express.static(distPath));
  app.get('*', (req, res) => {
    res.sendFile(path.join(distPath, 'index.html'));
  });
}

app.listen(PORT, () => {
  console.log(`[Certificate Authority Engine] Running on port ${PORT}`);
});
