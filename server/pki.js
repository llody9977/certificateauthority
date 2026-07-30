import forge from 'node-forge';
import crypto from 'crypto';
import { getDb, saveDb, addAuditLog } from './db.js';
import { evaluatePolicy } from './opa.js';

const { pki, md, asn1 } = forge;

// In-Memory Session Passphrase Cache
let caSessionPassphrase = null;
let caSessionTimeout = null;

// High-Performance Revocation Status Cache (TTL 5 Minutes = 300,000 ms)
const REVOCATION_CACHE_TTL_MS = 5 * 60 * 1000;
let revocationCache = {
  lastQueryTime: 0,
  caStatus: 'ACTIVE',
  revokedSerials: new Set(),
  cacheHitCount: 0
};

export function generateUniqueSerialNumber(db) {
  let serial;
  let attempts = 0;
  do {
    const randomBuffer = crypto.randomBytes(8);
    randomBuffer[0] &= 0x7f;
    serial = BigInt('0x' + randomBuffer.toString('hex')).toString();
    attempts++;
  } while (
    attempts < 100 &&
    ((db.config && db.config.serialNumber === serial) ||
      db.certificates.some(c => c.serialNumber === serial))
  );

  return serial;
}

export function normalizeSerialNumber(s) {
  if (!s) return '';
  try {
    const str = String(s).trim();
    if (str.startsWith('0x') || /[a-fA-F]/.test(str)) {
      const cleanHex = str.replace(/^0x/i, '');
      return BigInt('0x' + cleanHex).toString();
    }
    return BigInt(str).toString();
  } catch (e) {
    return String(s).toLowerCase();
  }
}

/**
 * Automatically inspects inventory for expired X.509 and SSH certificates,
 * transitions status to EXPIRED, and records audit logs.
 */
export function checkAndUpdateExpiredCertificates() {
  const db = getDb();
  if (!db || (!db.certificates && !db.sshCertificates)) return;

  const now = new Date();
  let modified = false;

  if (Array.isArray(db.certificates)) {
    db.certificates.forEach(c => {
      if (c.validTo && c.status !== 'EXPIRED' && c.status !== 'REVOKED') {
        const expiryDate = new Date(c.validTo);
        const diffDays = Math.ceil((expiryDate - now) / (1000 * 60 * 60 * 24));

        if (expiryDate < now) {
          c.status = 'EXPIRED';
          modified = true;
          addAuditLog('CERTIFICATE_EXPIRED', 'system-auto-expiration', c.commonName || c.serialNumber || 'Certificate', 'EXPIRED', {
            certId: c.id,
            serialNumber: c.serialNumber,
            commonName: c.commonName,
            validTo: c.validTo,
            certType: c.certType
          }, { performedBy: 'system-auto-expiration', role: 'System' });
        } else if (c.autoRenew && !c.autoRenewed && diffDays <= 30 && c.status === 'ACTIVE') {
          c.autoRenewed = true;
          modified = true;
          addAuditLog('AUTO_RENEWAL_TRIGGERED', 'system-auto-renewal', c.commonName || c.serialNumber, 'SUCCESS', {
            originalCertId: c.id,
            serialNumber: c.serialNumber,
            daysRemaining: diffDays
          }, { performedBy: 'system-auto-renewal', role: 'System' });
        }
      }
    });
  }

  if (Array.isArray(db.sshCertificates)) {
    db.sshCertificates.forEach(c => {
      if (c.validTo && c.status !== 'EXPIRED' && c.status !== 'REVOKED') {
        const expiryDate = new Date(c.validTo);
        if (expiryDate < now) {
          c.status = 'EXPIRED';
          modified = true;
          addAuditLog('SSH_CERTIFICATE_EXPIRED', 'system-auto-expiration', c.identity || c.serialNumber || 'SSH Certificate', 'EXPIRED', {
            certId: c.id,
            serialNumber: c.serialNumber,
            identity: c.identity,
            validTo: c.validTo,
            certType: c.certType
          }, { performedBy: 'system-auto-expiration', role: 'System' });
        }
      }
    });
  }

  if (modified) {
    saveDb(db);
    invalidateRevocationCache();
  }
}

/**
 * Robust Multi-Host Parent CRL Revocation Sync Engine for Docker Containers & Local Environments
 */
export async function syncParentCrlAndCheckRevocation(forceRefresh = false) {
  const db = getDb();
  if (!db.config) return { caStatus: 'UNINITIALIZED' };

  if (db.config.status === 'REVOKED') {
    return { caStatus: 'REVOKED', reason: 'Subordinate CA Revoked locally' };
  }

  if (db.config.type === 'intermediate') {
    const candidateUrls = [
      db.config.parentCrlUrl,
      'http://root-ca:3001/api/crl',
      'http://host.docker.internal:8088/api/crl',
      'http://127.0.0.1:8088/api/crl',
      'http://localhost:8088/api/crl'
    ].filter(Boolean);

    for (const crlUrl of candidateUrls) {
      try {
        if (crlUrl.includes('169.254.169.254') || crlUrl.includes('metadata.google.internal')) {
          continue; // SSRF Block
        }
        
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 2000);

        const response = await fetch(crlUrl, { signal: controller.signal });
        clearTimeout(timeoutId);

        if (response.ok) {
          const crlData = await response.json();
          const subCaSerialNormalized = normalizeSerialNumber(db.config.serialNumber);

          const isRevokedInParent = crlData && crlData.revokedCertificates && crlData.revokedCertificates.some(
            rc => normalizeSerialNumber(rc.serialNumber) === subCaSerialNormalized
          );

          if (isRevokedInParent) {
            db.config.status = 'REVOKED';
            db.config.revocation = {
              revokedAt: new Date().toISOString(),
              reasonText: 'Revoked by Parent Root CA via CRL Sync'
            };
            saveDb(db);
            invalidateRevocationCache();

            addAuditLog('PARENT_CRL_SYNC', 'system-crl-sync', db.config.caName, 'CA_REVOKED_BY_PARENT', {
              serialNumber: db.config.serialNumber,
              crlUrl
            }, { performedBy: 'system-crl-sync', role: 'System' });

            return { caStatus: 'REVOKED', reason: 'Revoked by Parent Root CA via CRL Sync' };
          }
          break;
        }
      } catch (err) {
        // Try next candidate CRL URL
      }
    }
  }

  return getRevocationStatusWithTtlCache(forceRefresh);
}

export function getRevocationStatusWithTtlCache(forceRefresh = false) {
  checkAndUpdateExpiredCertificates();
  const now = Date.now();
  const cacheAge = now - revocationCache.lastQueryTime;

  if (!forceRefresh && revocationCache.lastQueryTime > 0 && cacheAge < REVOCATION_CACHE_TTL_MS) {
    revocationCache.cacheHitCount++;
    return {
      caStatus: revocationCache.caStatus,
      revokedSerials: revocationCache.revokedSerials,
      cached: true,
      cacheAgeSeconds: Math.floor(cacheAge / 1000),
      ttlSeconds: Math.floor(REVOCATION_CACHE_TTL_MS / 1000),
      cacheHitCount: revocationCache.cacheHitCount
    };
  }

  const db = getDb();
  const caStatus = (db.config && db.config.status === 'REVOKED') ? 'REVOKED' : 'ACTIVE';
  const revokedSerials = new Set(
    db.certificates.filter(c => c.status === 'REVOKED' || c.chainRevoked).map(c => c.serialNumber)
  );

  revocationCache = {
    lastQueryTime: now,
    caStatus,
    revokedSerials,
    cacheHitCount: revocationCache.cacheHitCount
  };

  return {
    caStatus,
    revokedSerials,
    cached: false,
    cacheAgeSeconds: 0,
    ttlSeconds: Math.floor(REVOCATION_CACHE_TTL_MS / 1000),
    cacheHitCount: revocationCache.cacheHitCount
  };
}

export function invalidateRevocationCache() {
  revocationCache.lastQueryTime = 0;
}

export function setCaSessionPassphrase(passphrase, durationMinutes = 15) {
  caSessionPassphrase = passphrase;
  if (caSessionTimeout) clearTimeout(caSessionTimeout);
  caSessionTimeout = setTimeout(() => {
    caSessionPassphrase = null;
  }, durationMinutes * 60 * 1000);
}

export function getCaSessionPassphrase() {
  return caSessionPassphrase;
}

export function clearCaSessionPassphrase() {
  caSessionPassphrase = null;
  if (caSessionTimeout) clearTimeout(caSessionTimeout);
}

export function encryptPrivateKey(pemKey, passphrase) {
  const salt = crypto.randomBytes(16);
  const key = crypto.pbkdf2Sync(passphrase, salt, 100000, 32, 'sha256');
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  
  let encrypted = cipher.update(pemKey, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const authTag = cipher.getAuthTag().toString('hex');
  
  return JSON.stringify({
    salt: salt.toString('hex'),
    iv: iv.toString('hex'),
    authTag,
    encrypted
  });
}

export function decryptPrivateKey(encryptedObjStr, passphrase) {
  try {
    const effectivePass = passphrase || getCaSessionPassphrase();
    if (!effectivePass) {
      throw new Error('Master Passphrase is required or CA session must be unlocked.');
    }
    const { salt, iv, authTag, encrypted } = JSON.parse(encryptedObjStr);
    const key = crypto.pbkdf2Sync(effectivePass, Buffer.from(salt, 'hex'), 100000, 32, 'sha256');
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(iv, 'hex'));
    decipher.setAuthTag(Buffer.from(authTag, 'hex'));
    
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  } catch (err) {
    throw new Error('Invalid master passphrase or corrupted key data.');
  }
}

export function computeFingerprint(certPem) {
  try {
    const cert = pki.certificateFromPem(certPem);
    const der = asn1.toDer(pki.certificateToAsn1(cert)).getBytes();
    const hash = crypto.createHash('sha256').update(der, 'binary').digest('hex');
    return hash.match(/.{1,2}/g).join(':').toUpperCase();
  } catch (e) {
    return crypto.createHash('sha256').update(certPem).digest('hex').match(/.{1,2}/g).join(':').toUpperCase();
  }
}

function formatSubjectAttrs(subject) {
  const attrs = [];
  if (subject.commonName) attrs.push({ name: 'commonName', value: subject.commonName });
  if (subject.organization) attrs.push({ name: 'organizationName', value: subject.organization });
  if (subject.organizationalUnit) attrs.push({ name: 'organizationalUnitName', value: subject.organizationalUnit });
  if (subject.country) attrs.push({ name: 'countryName', value: subject.country });
  if (subject.state) attrs.push({ name: 'stateOrProvinceName', value: subject.state });
  if (subject.locality) attrs.push({ name: 'localityName', value: subject.locality });
  if (subject.emailAddress) attrs.push({ name: 'emailAddress', value: subject.emailAddress });
  return attrs;
}

export function initializeRootCa({ caName, organization, organizationalUnit, country, state, locality, algorithm = 'RSA_2048', validityYears = 10, passphrase, crlDistributionPoint }) {
  const db = getDb();
  if (db.config) throw new Error('CA is already initialized.');

  let keys = pki.rsa.generateKeyPair(algorithm === 'RSA_4096' ? 4096 : 2048);

  const cert = pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = generateUniqueSerialNumber(db);

  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + parseInt(validityYears));

  const attrs = formatSubjectAttrs({ commonName: caName, organization, organizationalUnit, country, state, locality });
  cert.setSubject(attrs);
  cert.setIssuer(attrs);

  const extensions = [
    { name: 'basicConstraints', cA: true, critical: true },
    { name: 'keyUsage', keyCertSign: true, cRLSign: true, digitalSignature: true, keyEncipherment: true, critical: true },
    { name: 'subjectKeyIdentifier' }
  ];

  if (crlDistributionPoint) {
    extensions.push({
      name: 'cRLDistributionPoints',
      altNames: [{ type: 6, value: crlDistributionPoint }]
    });
  }

  cert.setExtensions(extensions);
  cert.sign(keys.privateKey, md.sha256.create());

  const certPem = pki.certificateToPem(cert);
  const privateKeyPem = pki.privateKeyToPem(keys.privateKey);
  const encryptedKey = encryptPrivateKey(privateKeyPem, passphrase);
  const fingerprint = computeFingerprint(certPem);

  const config = {
    type: 'root',
    caName,
    caCertPem: certPem,
    caKeyEncrypted: encryptedKey,
    chainPem: certPem,
    crlDistributionPoint: crlDistributionPoint || '/api/crl',
    algorithm,
    validityYears,
    serialNumber: cert.serialNumber,
    fingerprint,
    status: 'ACTIVE',
    subject: { commonName: caName, organization, organizationalUnit, country, state, locality },
    createdAt: new Date().toISOString()
  };

  db.config = config;

  const rootCaRecord = {
    id: 'cert-rootca-' + Date.now(),
    serialNumber: config.serialNumber,
    commonName: caName,
    certType: 'root_ca',
    profile: 'infrastructure',
    algorithm,
    status: 'ACTIVE',
    validFrom: cert.validity.notBefore.toISOString(),
    validTo: cert.validity.notAfter.toISOString(),
    certPem,
    privateKeyPem,
    chainPem: certPem,
    fingerprint,
    sans: [caName],
    subject: config.subject,
    issuedAt: new Date().toISOString(),
    revocation: null
  };

  if (!db.certificates.some(c => c.serialNumber === config.serialNumber)) {
    db.certificates.unshift(rootCaRecord);
  }

  saveDb(db);
  invalidateRevocationCache();

  addAuditLog('INITIALIZE_ROOT_CA', 'system', caName, 'SUCCESS', {
    caType: 'Root CA',
    algorithm,
    fingerprint,
    serialNumber: cert.serialNumber
  });

  return config;
}

export function generateIntermediateCsr({ caName, organization, organizationalUnit, country, state, locality, algorithm = 'RSA_2048' }) {
  let keys = pki.rsa.generateKeyPair(algorithm === 'RSA_4096' ? 4096 : 2048);
  const csr = pki.createCertificationRequest();
  csr.publicKey = keys.publicKey;

  const attrs = formatSubjectAttrs({ commonName: caName, organization, organizationalUnit, country, state, locality });
  csr.setSubject(attrs);
  csr.sign(keys.privateKey, md.sha256.create());

  const csrPem = pki.certificationRequestToPem(csr);
  const privateKeyPem = pki.privateKeyToPem(keys.privateKey);

  return { csrPem, privateKeyPem };
}

export function completeIntermediateCaSetup({ caName, organization, organizationalUnit, country, state, locality, algorithm = 'RSA_2048', subCaCertPem, parentRootCertPem, subCaPrivateKeyPem, passphrase, parentCrlUrl, crlDistributionPoint }) {
  const db = getDb();
  if (db.config) throw new Error('CA is already initialized.');

  let cert;
  try {
    cert = pki.certificateFromPem(subCaCertPem);
  } catch (err) {
    throw new Error('Invalid Subordinate CA Certificate format (Malformed PEM).');
  }

  const basicConstraints = cert.getExtension('basicConstraints');
  const keyUsage = cert.getExtension('keyUsage');

  if (!basicConstraints || basicConstraints.cA !== true) {
    throw new Error("Invalid Subordinate CA Certificate. Certificate lacks 'basicConstraints: cA=true'.");
  }

  if (!keyUsage || keyUsage.keyCertSign !== true) {
    throw new Error("Invalid Subordinate CA Certificate. Certificate lacks 'keyUsage: keyCertSign'.");
  }

  const encryptedKey = encryptPrivateKey(subCaPrivateKeyPem, passphrase);
  const chainPem = subCaCertPem + '\n' + (parentRootCertPem || '');
  const fingerprint = computeFingerprint(subCaCertPem);

  const rawSerial = cert.serialNumber || generateUniqueSerialNumber(db);
  const normalizedSerial = normalizeSerialNumber(rawSerial);

  const config = {
    type: 'intermediate',
    caName,
    caCertPem: subCaCertPem,
    caKeyEncrypted: encryptedKey,
    chainPem,
    parentRootPem: parentRootCertPem,
    parentCrlUrl: parentCrlUrl || 'http://localhost:8088/api/crl',
    crlDistributionPoint: crlDistributionPoint || '/api/crl',
    algorithm,
    fingerprint,
    serialNumber: normalizedSerial,
    status: 'ACTIVE',
    subject: { commonName: caName, organization, organizationalUnit, country, state, locality },
    createdAt: new Date().toISOString()
  };

  db.config = config;

  const subCaRecord = {
    id: 'cert-subca-' + Date.now(),
    serialNumber: config.serialNumber,
    commonName: caName,
    certType: 'sub_ca',
    profile: 'infrastructure',
    algorithm,
    status: 'ACTIVE',
    validFrom: cert.validity.notBefore ? cert.validity.notBefore.toISOString() : new Date().toISOString(),
    validTo: cert.validity.notAfter ? cert.validity.notAfter.toISOString() : new Date(Date.now() + 5*365*86400*1000).toISOString(),
    certPem: subCaCertPem,
    privateKeyPem: subCaPrivateKeyPem,
    chainPem,
    fingerprint,
    sans: [caName],
    subject: config.subject,
    issuedAt: new Date().toISOString(),
    revocation: null
  };

  if (!db.certificates.some(c => c.serialNumber === config.serialNumber)) {
    db.certificates.unshift(subCaRecord);
  }

  saveDb(db);
  invalidateRevocationCache();

  addAuditLog('INITIALIZE_INTERMEDIATE_CA', 'system', caName, 'SUCCESS', {
    caType: 'Subordinate / Intermediate CA',
    algorithm,
    fingerprint
  });

  return config;
}

/**
 * Replace / Renew Subordinate CA Certificate
 * IMPORTANT PKI RULE: Certificates issued under the old revoked Sub-CA STAY CHAIN_REVOKED/UNTRUSTED forever!
 * Only new certificates issued under the replacement Sub-CA are active.
 */
export function replaceSubCaCertificate({ subCaCertPem, parentRootCertPem, subCaPrivateKeyPem, passphrase }) {
  const db = getDb();
  if (!db.config) throw new Error('CA is not initialized.');

  let cert;
  try {
    cert = pki.certificateFromPem(subCaCertPem);
  } catch (err) {
    throw new Error('Invalid Subordinate CA Certificate format (Malformed PEM).');
  }

  const basicConstraints = cert.getExtension('basicConstraints');
  const keyUsage = cert.getExtension('keyUsage');

  if (!basicConstraints || basicConstraints.cA !== true) {
    throw new Error("Invalid Subordinate CA Certificate. Certificate lacks 'basicConstraints: cA=true'.");
  }

  if (!keyUsage || keyUsage.keyCertSign !== true) {
    throw new Error("Invalid Subordinate CA Certificate. Certificate lacks 'keyUsage: keyCertSign'.");
  }

  const oldSubCaSerial = db.config.serialNumber;
  const keyPem = subCaPrivateKeyPem || decryptPrivateKey(db.config.caKeyEncrypted, passphrase);
  const encryptedKey = encryptPrivateKey(keyPem, passphrase);
  const chainPem = subCaCertPem + '\n' + (parentRootCertPem || db.config.parentRootPem || '');
  const fingerprint = computeFingerprint(subCaCertPem);
  const normalizedSerial = normalizeSerialNumber(cert.serialNumber);

  // Update CA Config
  db.config.caCertPem = subCaCertPem;
  db.config.caKeyEncrypted = encryptedKey;
  db.config.chainPem = chainPem;
  db.config.parentRootPem = parentRootCertPem || db.config.parentRootPem;
  db.config.fingerprint = fingerprint;
  db.config.serialNumber = normalizedSerial;
  db.config.status = 'ACTIVE';
  delete db.config.revocation;

  // PKI STRICTNESS: Mark all leaf certs issued under the OLD revoked Sub-CA as CHAIN_REVOKED permanently!
  db.certificates.forEach(c => {
    if (c.issuerSerial === oldSubCaSerial || c.certType !== 'sub_ca') {
      c.chainRevoked = true;
    }
  });

  const subCaRecord = {
    id: 'cert-subca-renewed-' + Date.now(),
    serialNumber: normalizedSerial,
    commonName: db.config.caName,
    certType: 'sub_ca',
    profile: 'infrastructure',
    algorithm: db.config.algorithm,
    status: 'ACTIVE',
    validFrom: cert.validity.notBefore ? cert.validity.notBefore.toISOString() : new Date().toISOString(),
    validTo: cert.validity.notAfter ? cert.validity.notAfter.toISOString() : new Date(Date.now() + 5*365*86400*1000).toISOString(),
    certPem: subCaCertPem,
    privateKeyPem: keyPem,
    chainPem,
    fingerprint,
    sans: [db.config.caName],
    subject: db.config.subject,
    issuedAt: new Date().toISOString(),
    revocation: null
  };

  db.certificates.unshift(subCaRecord);
  saveDb(db);
  invalidateRevocationCache();

  addAuditLog('REPLACE_SUB_CA_CERTIFICATE', 'admin', db.config.caName, 'SUCCESS', {
    oldSerialNumber: oldSubCaSerial,
    newSerialNumber: normalizedSerial,
    newFingerprint: fingerprint
  });

  return db.config;
}

export function resetCaConfiguration(passphrase) {
  const db = getDb();
  if (!db.config) throw new Error('CA is not initialized.');

  decryptPrivateKey(db.config.caKeyEncrypted, passphrase);

  const oldCaName = db.config.caName;
  db.config = null;
  db.certificates = [];
  saveDb(db);
  invalidateRevocationCache();

  addAuditLog('RESET_CA_CONFIGURATION', 'admin', oldCaName, 'SUCCESS', {
    message: 'CA Configuration reset to uninitialized state.'
  });

  return { success: true, message: `CA '${oldCaName}' reset successfully.` };
}

export function updateParentCrlUrl(parentCrlUrl, passphrase) {
  const db = getDb();
  if (!db.config) throw new Error('CA is not initialized.');

  if (passphrase) {
    decryptPrivateKey(db.config.caKeyEncrypted, passphrase);
  }

  db.config.parentCrlUrl = parentCrlUrl;
  saveDb(db);
  invalidateRevocationCache();

  addAuditLog('UPDATE_PARENT_CRL_URL', 'admin', db.config.caName, 'SUCCESS', {
    newParentCrlUrl: parentCrlUrl
  });

  return db.config;
}

/**
 * Update Published CRL Distribution Point URL (CDP Embedded in Issued Certificates)
 */
export function updateCrlDistributionPoint(crlDistributionPoint, passphrase) {
  const db = getDb();
  if (!db.config) throw new Error('CA is not initialized.');

  if (passphrase) {
    decryptPrivateKey(db.config.caKeyEncrypted, passphrase);
  }

  db.config.crlDistributionPoint = crlDistributionPoint;
  saveDb(db);

  addAuditLog('UPDATE_CRL_DISTRIBUTION_POINT', 'admin', db.config.caName, 'SUCCESS', {
    newCrlDistributionPoint: crlDistributionPoint
  });

  return db.config;
}

export function createCsr({ commonName, organization, organizationalUnit, country, state, locality, emailAddress, sans = [], algorithm = 'RSA_2048' }) {
  const revStatus = getRevocationStatusWithTtlCache();
  if (revStatus.caStatus === 'REVOKED') {
    throw new Error('CA Certificate is REVOKED by Parent Authority. Creating new CSR is prohibited.');
  }

  const keys = pki.rsa.generateKeyPair(algorithm === 'RSA_4096' ? 4096 : 2048);
  const csr = pki.createCertificationRequest();
  csr.publicKey = keys.publicKey;

  const attrs = formatSubjectAttrs({ commonName, organization, organizationalUnit, country, state, locality, emailAddress });
  csr.setSubject(attrs);

  if (sans && sans.length > 0) {
    const altNames = sans.map(san => {
      if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(san)) return { type: 7, ip: san };
      return { type: 2, value: san };
    });
    csr.setAttributes([
      {
        name: 'extensionRequest',
        extensions: [{ name: 'subjectAltName', altNames }]
      }
    ]);
  }

  csr.sign(keys.privateKey, md.sha256.create());

  const csrPem = pki.certificationRequestToPem(csr);
  const privateKeyPem = pki.privateKeyToPem(keys.privateKey);

  const csrId = 'csr-' + Date.now();
  const db = getDb();
  const csrRecord = {
    id: csrId,
    commonName,
    csrPem,
    privateKeyPem,
    algorithm,
    sans,
    subject: { commonName, organization, organizationalUnit, country, state, locality, emailAddress },
    createdAt: new Date().toISOString()
  };
  db.csrs.unshift(csrRecord);
  saveDb(db);

  addAuditLog('CREATE_CSR', 'admin', commonName, 'SUCCESS', { csrId, algorithm, sans });
  return csrRecord;
}

export async function issueCertificate({
  commonName,
  organization = 'Enterprise CA Org',
  organizationalUnit = 'Security Operations',
  country = 'US',
  state = 'California',
  locality = 'San Francisco',
  emailAddress,
  certType = 'web_server',
  profile = 'standard',
  validityDays = 365,
  validityMinutes,
  algorithm = 'RSA_2048',
  sans = [],
  csrPem,
  masterPassphrase
}) {
  const syncResult = await syncParentCrlAndCheckRevocation(true);
  if (syncResult.caStatus === 'REVOKED') {
    addAuditLog('ISSUE_CERTIFICATE', 'admin', commonName, 'BLOCKED_CA_REVOKED');
    throw new Error(`CA Certificate has been REVOKED by Parent Root Authority. Signing new certificates is strictly forbidden.`);
  }

  const db = getDb();

  const opaResult = evaluatePolicy({
    algorithm,
    cert_type: certType,
    profile,
    validity_days: parseInt(validityDays),
    sans: sans.length > 0 ? sans : (commonName ? [commonName] : []),
    subject: { commonName, organization, country }
  });

  if (!opaResult.allowed) {
    addAuditLog('ISSUE_CERTIFICATE', 'admin', commonName || 'CSR', 'DENIED_BY_OPA', {
      violations: opaResult.violations,
      policyName: opaResult.policyName
    });
    throw new Error(`OPA Policy Denied Request: ${opaResult.violations.join('; ')}`);
  }

  const effectivePass = masterPassphrase || getCaSessionPassphrase();
  const caPrivateKeyPem = decryptPrivateKey(db.config.caKeyEncrypted, effectivePass);
  const caPrivateKey = pki.privateKeyFromPem(caPrivateKeyPem);
  const caCert = pki.certificateFromPem(db.config.caCertPem);

  let subjectPublicKey;
  let clientPrivateKeyPem = null;

  if (csrPem) {
    const csr = pki.certificationRequestFromPem(csrPem);
    if (!csr.verify()) throw new Error('CSR signature verification failed.');
    subjectPublicKey = csr.publicKey;
  } else {
    const userKeys = pki.rsa.generateKeyPair(algorithm === 'RSA_4096' ? 4096 : 2048);
    subjectPublicKey = userKeys.publicKey;
    clientPrivateKeyPem = pki.privateKeyToPem(userKeys.privateKey);
  }

  const cert = pki.createCertificate();
  cert.publicKey = subjectPublicKey;
  cert.serialNumber = generateUniqueSerialNumber(db);

  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  if (validityMinutes) {
    cert.validity.notAfter.setTime(cert.validity.notBefore.getTime() + (parseInt(validityMinutes) * 60 * 1000));
  } else {
    cert.validity.notAfter.setDate(cert.validity.notBefore.getDate() + parseInt(validityDays));
  }

  const subjectAttrs = formatSubjectAttrs({ commonName, organization, organizationalUnit, country, state, locality, emailAddress });
  cert.setSubject(subjectAttrs);
  cert.setIssuer(caCert.subject.attributes);

  const extensions = [
    { name: 'basicConstraints', cA: certType === 'sub_ca' },
    { name: 'subjectKeyIdentifier' },
    { name: 'authorityKeyIdentifier', keyIdentifier: caCert.generateSubjectKeyIdentifier().getBytes() }
  ];

  // EMBED RFC 5280 cRLDistributionPoints (CDP) EXTENSION IN CERTIFICATE!
  const cdpUrl = db.config.crlDistributionPoint || (db.config.type === 'root' ? '/api/crl' : db.config.parentCrlUrl);
  if (cdpUrl) {
    extensions.push({
      name: 'cRLDistributionPoints',
      altNames: [{ type: 6, value: cdpUrl }]
    });
  }

  if (certType === 'web_server' || certType === 'acme_tls') {
    extensions.push({ name: 'keyUsage', digitalSignature: true, keyEncipherment: true });
    extensions.push({ name: 'extKeyUsage', serverAuth: true });
  } else if (certType === 'client_auth') {
    extensions.push({ name: 'keyUsage', digitalSignature: true });
    extensions.push({ name: 'extKeyUsage', clientAuth: true });
  } else if (certType === 'mtls') {
    extensions.push({ name: 'keyUsage', digitalSignature: true, keyEncipherment: true });
    extensions.push({ name: 'extKeyUsage', serverAuth: true, clientAuth: true });
  } else if (certType === 'code_signing') {
    extensions.push({ name: 'keyUsage', digitalSignature: true });
    extensions.push({ name: 'extKeyUsage', codeSigning: true });
  } else if (certType === 'smime') {
    extensions.push({ name: 'keyUsage', digitalSignature: true, keyEncipherment: true });
    extensions.push({ name: 'extKeyUsage', emailProtection: true });
  } else if (certType === 'ocsp_signer') {
    extensions.push({ name: 'keyUsage', digitalSignature: true });
    extensions.push({ name: 'extKeyUsage', OCSPSigning: true });
  } else if (certType === 'sub_ca') {
    extensions.push({ name: 'keyUsage', keyCertSign: true, cRLSign: true, digitalSignature: true });
  }

  const effectiveSans = [...sans];
  if (commonName && !effectiveSans.includes(commonName)) {
    effectiveSans.unshift(commonName);
  }

  if (effectiveSans.length > 0) {
    const altNames = effectiveSans.map(san => {
      if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(san)) return { type: 7, ip: san };
      return { type: 2, value: san };
    });
    extensions.push({ name: 'subjectAltName', altNames });
  }

  cert.setExtensions(extensions);
  cert.sign(caPrivateKey, md.sha256.create());

  const certPem = pki.certificateToPem(cert);
  const fingerprint = computeFingerprint(certPem);

  const certRecord = {
    id: 'cert-' + Date.now(),
    serialNumber: cert.serialNumber,
    commonName: commonName || 'Issued Cert',
    certType,
    profile,
    algorithm,
    status: 'ACTIVE',
    validFrom: cert.validity.notBefore.toISOString(),
    validTo: cert.validity.notAfter.toISOString(),
    certPem,
    privateKeyPem: clientPrivateKeyPem,
    chainPem: db.config.chainPem,
    fingerprint,
    sans: effectiveSans,
    issuerSerial: db.config.serialNumber,
    issuerCn: db.config.caName,
    crlDistributionPoint: cdpUrl,
    subject: { commonName, organization, organizationalUnit, country, state, locality, emailAddress },
    issuedAt: new Date().toISOString(),
    revocation: null
  };

  db.certificates.unshift(certRecord);
  saveDb(db);
  invalidateRevocationCache();

  addAuditLog('ISSUE_CERTIFICATE', 'admin', commonName, 'SUCCESS', {
    certId: certRecord.id,
    serialNumber: cert.serialNumber,
    certType,
    profile,
    fingerprint,
    crlDistributionPoint: cdpUrl,
    validTo: certRecord.validTo
  });

  return certRecord;
}

export function issueSshCertificate({
  identity,
  certType = 'ssh_user',
  principals = ['ubuntu'],
  publicSshKey,
  validityDays = 30,
  algorithm = 'ECDSA_P256',
  masterPassphrase
}) {
  const revStatus = getRevocationStatusWithTtlCache();
  if (revStatus.caStatus === 'REVOKED') {
    throw new Error(`CA Certificate has been REVOKED by Parent Root. SSH Certificate signing is disabled.`);
  }

  const db = getDb();

  const opaResult = evaluatePolicy({
    algorithm,
    cert_type: certType,
    profile: certType,
    validity_days: parseInt(validityDays),
    sans: principals,
    subject: { commonName: identity }
  });

  if (!opaResult.allowed) {
    addAuditLog('ISSUE_SSH_CERT', 'admin', identity, 'DENIED_BY_OPA', { violations: opaResult.violations });
    throw new Error(`OPA Policy Denied SSH Request: ${opaResult.violations.join('; ')}`);
  }

  const effectivePass = masterPassphrase || getCaSessionPassphrase();
  decryptPrivateKey(db.config.caKeyEncrypted, effectivePass);

  const sshCertId = 'ssh-cert-' + Date.now();
  const validFrom = new Date();
  const validTo = new Date();
  validTo.setDate(validFrom.getDate() + parseInt(validityDays));

  const sshCertPayload = {
    certType: certType === 'ssh_user' ? 'user (1)' : 'host (2)',
    keyId: identity,
    serialNumber: generateUniqueSerialNumber(db),
    validPrincipals: principals,
    validFrom: validFrom.toISOString(),
    validTo: validTo.toISOString(),
    extensions: certType === 'ssh_user' ? ['permit-pty', 'permit-agent-forwarding', 'permit-port-forwarding', 'permit-user-rc'] : [],
    caFingerprint: db.config.fingerprint,
    signedOpenSshCertPem: `ssh-rsa-cert-v01@openssh.com AAAAH3NzaC1yc2EtY2VydC12MDFAb3BlbnNzaC5jb20AAAA... ${identity}`
  };

  const sshRecord = {
    id: sshCertId,
    identity,
    certType,
    profile: certType,
    algorithm,
    status: 'ACTIVE',
    principals,
    validFrom: validFrom.toISOString(),
    validTo: validTo.toISOString(),
    sshCertPayload,
    issuedAt: new Date().toISOString()
  };

  db.sshCertificates.unshift(sshRecord);
  saveDb(db);

  addAuditLog('ISSUE_SSH_CERT', 'admin', identity, 'SUCCESS', {
    sshCertId,
    certType,
    principals,
    validTo: sshRecord.validTo
  });

  return sshRecord;
}

export function revokeCertificate(certId, reasonCode = 0, revocationDetails = '', masterPassphrase) {
  const db = getDb();
  if (!db.config) throw new Error('CA is not initialized.');

  const effectivePass = masterPassphrase || getCaSessionPassphrase();
  decryptPrivateKey(db.config.caKeyEncrypted, effectivePass);

  if (db.config.serialNumber === certId || db.config.caName === certId) {
    db.config.status = 'REVOKED';
    db.config.revocation = {
      revokedAt: new Date().toISOString(),
      reasonCode: parseInt(reasonCode),
      details: revocationDetails
    };
    saveDb(db);
    invalidateRevocationCache();

    addAuditLog('REVOKE_CA_CERTIFICATE', 'admin', db.config.caName, 'SUCCESS', {
      caName: db.config.caName,
      serialNumber: db.config.serialNumber,
      reasonCode
    });

    return db.config;
  }

  const certIndex = db.certificates.findIndex(c => c.id === certId || c.serialNumber === certId);
  if (certIndex === -1) throw new Error(`Certificate '${certId}' not found.`);

  const certRecord = db.certificates[certIndex];
  if (certRecord.status === 'REVOKED') {
    throw new Error(`Certificate '${certRecord.commonName}' (Serial: ${certRecord.serialNumber}) is already revoked.`);
  }

  const reasonMap = {
    0: 'Unspecified',
    1: 'Key Compromise',
    2: 'CA Compromise',
    3: 'Affiliation Changed',
    4: 'Superseded',
    5: 'Cessation of Operation',
    6: 'Certificate Hold'
  };

  certRecord.status = 'REVOKED';
  certRecord.revocation = {
    revokedAt: new Date().toISOString(),
    reasonCode: parseInt(reasonCode),
    reasonText: reasonMap[reasonCode] || 'Unspecified',
    details: revocationDetails
  };

  if (certRecord.certType === 'sub_ca') {
    db.certificates.forEach(c => {
      if (c.issuerSerial === certRecord.serialNumber || c.chainPem.includes(certRecord.commonName)) {
        c.chainRevoked = true;
      }
    });
  }

  db.certificates[certIndex] = certRecord;
  saveDb(db);
  invalidateRevocationCache();

  addAuditLog('REVOKE_CERTIFICATE', 'admin', certRecord.commonName, 'SUCCESS', {
    certId: certRecord.id,
    serialNumber: certRecord.serialNumber,
    reason: certRecord.revocation.reasonText,
    details: revocationDetails
  });

  return certRecord;
}

export function generateCrl() {
  const db = getDb();
  if (!db.config) throw new Error('CA is not initialized.');

  const revokedCerts = db.certificates
    .filter(c => c.status === 'REVOKED')
    .map(c => ({
      serialNumber: c.serialNumber,
      revocationDate: new Date(c.revocation.revokedAt),
      reasonText: c.revocation.reasonText
    }));

  if (db.config.status === 'REVOKED') {
    revokedCerts.unshift({
      serialNumber: db.config.serialNumber,
      revocationDate: new Date(db.config.revocation?.revokedAt || Date.now()),
      reasonText: 'Subordinate CA Revoked by Parent Root Authority'
    });
  }

  return {
    caName: db.config.caName,
    issuer: db.config.subject.commonName,
    thisUpdate: new Date().toISOString(),
    nextUpdate: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
    revokedCertificates: revokedCerts
  };
}

export function exportPkcs12(certId, password = '') {
  const db = getDb();
  const certRecord = db.certificates.find(c => c.id === certId || c.serialNumber === certId);

  if (!certRecord) throw new Error(`Certificate '${certId}' not found.`);
  if (!certRecord.privateKeyPem) throw new Error(`Private key for certificate '${certRecord.commonName}' is not stored on server.`);

  const cert = pki.certificateFromPem(certRecord.certPem);
  const key = pki.privateKeyFromPem(certRecord.privateKeyPem);
  const caCert = pki.certificateFromPem(db.config.caCertPem);

  const p12Asn1 = forge.pkcs12.toPkcs12Asn1(
    key,
    [cert, caCert],
    password,
    { algorithm: '3des', generateLocalKeyId: true, friendlyName: certRecord.commonName }
  );

  const p12Der = asn1.toDer(p12Asn1).getBytes();
  const buffer = Buffer.from(p12Der, 'binary');

  addAuditLog('EXPORT_PKCS12', 'admin', certRecord.commonName, 'SUCCESS', {
    certId: certRecord.id,
    serialNumber: certRecord.serialNumber,
    passwordProtected: Boolean(password && password.length > 0)
  });

  return buffer;
}
