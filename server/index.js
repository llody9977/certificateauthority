import express from 'express';
import cors from 'cors';
import path from 'path';
import fs from 'fs';
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
  updateCrlDistributionPoint
} from './pki.js';
import { evaluatePolicy } from './opa.js';

const app = express();
const PORT = process.env.PORT || 8088;

app.use(cors());
app.use(express.json({ limit: '10mb' }));

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

// 4. Setup Intermediate CA Step 2
app.post('/api/setup/intermediate-complete', (req, res) => {
  try {
    const { caName, organization, organizationalUnit, country, state, locality, algorithm, subCaCertPem, parentRootCertPem, subCaPrivateKeyPem, passphrase } = req.body;

    if (!subCaCertPem || !subCaPrivateKeyPem || !passphrase) {
      return res.status(400).json({ error: 'Sub-CA Certificate, Private Key, and Master Passphrase are required.' });
    }

    const config = completeIntermediateCaSetup({
      caName,
      organization,
      organizationalUnit,
      country,
      state,
      locality,
      algorithm,
      subCaCertPem,
      parentRootCertPem: parentRootCertPem || subCaCertPem,
      subCaPrivateKeyPem,
      passphrase
    });

    const { caKeyEncrypted, ...safeConfig } = config;
    res.json({ success: true, config: safeConfig });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// 4b. Replace / Renew Sub-CA Certificate
app.post('/api/setup/replace-cert', (req, res) => {
  try {
    const { subCaCertPem, parentRootCertPem, subCaPrivateKeyPem, passphrase } = req.body;
    if (!subCaCertPem) {
      return res.status(400).json({ error: 'Replacement Sub-CA Certificate PEM is required.' });
    }

    const config = replaceSubCaCertificate({ subCaCertPem, parentRootCertPem, subCaPrivateKeyPem, passphrase });
    const { caKeyEncrypted, ...safeConfig } = config;
    res.json({ success: true, message: 'Sub-CA Certificate replaced and restored to ACTIVE status.', config: safeConfig });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// 4c. Reset CA Configuration (Decommission & Re-initialize)
app.post('/api/setup/reset', (req, res) => {
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
  const db = getDb();

  // Sync Parent CRL if Intermediate CA
  await syncParentCrlAndCheckRevocation();

  const { query, status, certType, profile, algorithm, includeSelfAnchor } = req.query;

  let certs = db.certificates;

  // Filter out Root CA self-anchor unless explicitly requested
  if (includeSelfAnchor !== 'true') {
    certs = certs.filter(c => c.certType !== 'root_ca');
  }

  if (status) certs = certs.filter(c => c.status === status.toUpperCase());
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
    return {
      ...safe,
      hasPrivateKey: Boolean(privateKeyPem),
      effectiveStatus: (db.config && db.config.status === 'REVOKED') || c.chainRevoked ? 'CHAIN_REVOKED' : c.status
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

// 7. Issue Certificate Endpoint (OPA Policy Protected)
app.post('/api/certificates/issue', async (req, res) => {
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
app.post('/api/certificates/revoke', (req, res) => {
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

// 17. CA Chain Download
app.get('/api/ca/chain', (req, res) => {
  const db = getDb();
  if (!db.config) return res.status(404).json({ error: 'CA is not initialized' });

  res.setHeader('Content-Type', 'application/x-pem-file');
  res.setHeader('Content-Disposition', `attachment; filename="${db.config.caName || 'ca-chain'}.pem"`);
  res.send(db.config.chainPem || db.config.caCertPem);
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
