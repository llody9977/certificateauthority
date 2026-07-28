import forge from 'node-forge';
import { getDb, addAuditLog } from './db.js';
import { issueCertificate } from './pki.js';
import { evaluatePolicy } from './opa.js';

const { pki } = forge;

/**
 * Enrollment over Secure Transport (EST - RFC 7030) Engine
 * Standard endpoints:
 * - GET /.well-known/est/cacerts
 * - POST /.well-known/est/simpleenroll
 */

export function handleEstCacerts(req, res) {
  const db = getDb();
  if (!db.config || !db.config.caCertPem) {
    return res.status(503).send('CA Not Initialized');
  }

  // RFC 7030 specifies application/pkcs7-mime or text/plain base64 output
  const format = req.query.format || 'pem';
  if (format === 'pem') {
    res.setHeader('Content-Type', 'application/x-pem-file');
    return res.send(db.config.chainPem || db.config.caCertPem);
  }

  res.setHeader('Content-Type', 'application/pkcs7-mime');
  res.setHeader('Content-Transfer-Encoding', 'base64');
  const base64Chain = Buffer.from(db.config.chainPem || db.config.caCertPem).toString('base64');
  res.send(base64Chain);
}

export async function handleEstSimpleEnroll(req, res, metaContext = {}) {
  try {
    const db = getDb();
    if (!db.config || db.config.status === 'REVOKED') {
      return res.status(503).send('CA Unavailable or Revoked');
    }

    let csrPem = req.body;
    if (typeof csrPem === 'object' && csrPem.csrPem) {
      csrPem = csrPem.csrPem;
    }
    if (Buffer.isBuffer(csrPem)) {
      csrPem = csrPem.toString('utf-8');
    }

    if (typeof csrPem !== 'string' || !csrPem.includes('CERTIFICATE REQUEST')) {
      // Decode base64 if needed
      try {
        const decoded = Buffer.from(csrPem, 'base64').toString('utf-8');
        if (decoded.includes('CERTIFICATE REQUEST')) {
          csrPem = decoded;
        }
      } catch (e) {}
    }

    if (!csrPem || typeof csrPem !== 'string' || !csrPem.includes('CERTIFICATE REQUEST')) {
      return res.status(400).send('Invalid PKCS#10 CSR in request body');
    }

    // Parse CSR details
    const csr = pki.certificationRequestFromPem(csrPem);
    const cnAttr = csr.subject.attributes.find(a => a.name === 'commonName' || a.shortName === 'CN');
    const commonName = cnAttr ? cnAttr.value : 'est-device.internal';

    // Issue Certificate under OPA Policy Governance
    const certRecord = await issueCertificate({
      commonName,
      certType: 'client_auth',
      profile: 'standard',
      validityDays: 365,
      csrPem,
      masterPassphrase: metaContext.masterPassphrase
    });

    addAuditLog('EST_SIMPLE_ENROLL', metaContext.performedBy || 'est-device', commonName, 'SUCCESS', {
      serialNumber: certRecord.serialNumber,
      certId: certRecord.id
    }, metaContext);

    res.setHeader('Content-Type', 'application/pkcs7-mime');
    res.setHeader('Content-Transfer-Encoding', 'base64');
    const certBase64 = Buffer.from(certRecord.certPem).toString('base64');
    res.send(certBase64);
  } catch (err) {
    res.status(400).send(`EST Enrollment Failed: ${err.message}`);
  }
}
