import { getDb } from './db.js';

/**
 * Form-based OPA Policy evaluator supporting X.509, ACME TLS, and SSH User/Host credentials
 */
export function evaluatePolicy(requestData) {
  const db = getDb();
  const activePolicy = db.opaPolicies.find(p => p.enabled);

  if (!activePolicy) {
    return {
      allowed: true,
      reason: 'No active OPA policy enforced.'
    };
  }

  const settings = activePolicy.settings || {
    allowedAlgorithms: ['ECDSA_P256', 'ECDSA_P384', 'RSA_2048', 'RSA_4096', 'ED25519'],
    allowedCertTypes: ['web_server', 'client_auth', 'mtls', 'code_signing', 'smime', 'ocsp_signer', 'sub_ca', 'acme_tls', 'ssh_user', 'ssh_host'],
    maxDaysByProfile: { short_lived: 7, acme_tls: 90, standard: 365, infrastructure: 730, code_signing: 365, ssh_user: 30, ssh_host: 365 },
    allowWildcards: false,
    requireSan: true
  };

  const { algorithm, cert_type, profile, validity_days, sans = [], subject = {} } = requestData;

  const violations = [];

  // Rule 1: Algorithm Check
  if (!settings.allowedAlgorithms.includes(algorithm)) {
    violations.push(`Algorithm '${algorithm}' is not permitted by OPA policy. Approved: ${settings.allowedAlgorithms.join(', ')}`);
  }

  // Rule 2: Cert Type Check
  if (!settings.allowedCertTypes.includes(cert_type)) {
    violations.push(`Certificate type '${cert_type}' is forbidden by OPA policy. Approved types: ${settings.allowedCertTypes.join(', ')}`);
  }

  // Rule 3: Validity Profile Check
  const maxAllowedDays = settings.maxDaysByProfile[profile];
  if (!maxAllowedDays) {
    violations.push(`Unapproved or unconfigured profile '${profile}'. Custom validity duration without profile approval is forbidden by OPA policy.`);
  } else if (validity_days > maxAllowedDays) {
    violations.push(`Requested validity (${validity_days} days) exceeds maximum allowed (${maxAllowedDays} days) for profile '${profile}'.`);
  }

  // Rule 4: SAN Requirement Check
  const cn = subject.commonName || '';
  if (settings.requireSan && (!sans || sans.length === 0) && !cn) {
    violations.push(`Certificate request must specify at least one Subject Alternative Name (SAN) or Common Name.`);
  }

  // Rule 5: Wildcard SAN Check
  if (!settings.allowWildcards && profile !== 'infrastructure' && sans.some(san => san.startsWith('*.'))) {
    violations.push(`Wildcard SANs (e.g. *.domain.com) are disallowed by OPA policy unless using 'infrastructure' profile.`);
  }

  if (violations.length > 0) {
    return {
      allowed: false,
      reason: 'OPA Policy Enforcement Violation',
      violations,
      policyId: activePolicy.id,
      policyName: activePolicy.name
    };
  }

  return {
    allowed: true,
    reason: 'Complies with OPA Governance Policy',
    policyId: activePolicy.id,
    policyName: activePolicy.name
  };
}
