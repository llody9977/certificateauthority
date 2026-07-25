import fs from 'fs';
import path from 'path';

const DATA_DIR = path.join(process.cwd(), 'data');

if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

const DB_FILE = path.join(DATA_DIR, 'ca_database.json');

const defaultPolicySettings = {
  allowedAlgorithms: ['ECDSA_P256', 'ECDSA_P384', 'RSA_2048', 'RSA_4096', 'ED25519'],
  allowedCertTypes: ['web_server', 'client_auth', 'mtls', 'code_signing', 'smime', 'ocsp_signer', 'sub_ca', 'acme_tls', 'ssh_user', 'ssh_host'],
  maxDaysByProfile: {
    short_lived: 7,
    acme_tls: 90,
    standard: 365,
    infrastructure: 730,
    code_signing: 365,
    ocsp_signer: 180,
    ssh_user: 30,
    ssh_host: 365
  },
  allowWildcards: false,
  requireSan: true
};

export function generateRegoFromForm(settings) {
  const algsStr = JSON.stringify(settings.allowedAlgorithms);
  const typesStr = JSON.stringify(settings.allowedCertTypes);
  const profilesStr = JSON.stringify(settings.maxDaysByProfile, null, 4);

  return `package ca.issuance

default allow = false

# Approved Signature Algorithms
allowed_algorithms = ${algsStr}

# Allowed Certificate & Credential Types
allowed_types = ${typesStr}

# Maximum Validity Boundaries (Days)
max_days_by_profile = ${profilesStr}

# Security Constraints
allow_wildcards = ${settings.allowWildcards}
require_san = ${settings.requireSan}

allow {
    input.algorithm == allowed_algorithms[_]
    input.cert_type == allowed_types[_]
    input.validity_days <= max_days_by_profile[input.profile]
    valid_san_check
    valid_wildcard_check
}

valid_san_check {
    require_san == false
}

valid_san_check {
    require_san == true
    count(input.sans) > 0
}

valid_wildcard_check {
    allow_wildcards == true
}

valid_wildcard_check {
    allow_wildcards == false
    input.profile == "infrastructure"
}
`;
}

const defaultDb = {
  config: null,
  certificates: [],
  csrs: [],
  sshCertificates: [],
  opaPolicies: [
    {
      id: 'default-governance',
      name: 'Default Enterprise Compliance Policy',
      enabled: true,
      description: 'Form-driven policy enforcing algorithms, profile limits, SSH credentials, and ACME protocol limits.',
      settings: defaultPolicySettings,
      rego: generateRegoFromForm(defaultPolicySettings)
    }
  ],
  auditLogs: []
};

export function getDb() {
  if (!fs.existsSync(DB_FILE)) {
    saveDb(defaultDb);
    return defaultDb;
  }
  try {
    const raw = fs.readFileSync(DB_FILE, 'utf-8');
    const parsed = JSON.parse(raw);
    if (!parsed.sshCertificates) parsed.sshCertificates = [];
    return parsed;
  } catch (err) {
    console.error('Error reading DB file, resetting:', err);
    saveDb(defaultDb);
    return defaultDb;
  }
}

export function saveDb(data) {
  fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2), 'utf-8');
}

export function addAuditLog(action, actor, target, status, details = {}) {
  const db = getDb();
  const logEntry = {
    id: 'log-' + Date.now() + '-' + Math.random().toString(36).substring(2, 7),
    timestamp: new Date().toISOString(),
    action,
    actor: actor || 'admin',
    target: target || 'system',
    status: status || 'SUCCESS',
    details
  };
  db.auditLogs.unshift(logEntry);
  if (db.auditLogs.length > 1000) {
    db.auditLogs = db.auditLogs.slice(0, 1000);
  }
  saveDb(db);
  return logEntry;
}
