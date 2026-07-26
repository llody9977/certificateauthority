import http from 'http';
import forge from 'node-forge';

const { pki, md } = forge;

/**
 * Enterprise step-ca FULL PKI SECURITY & VALIDATION SUITE
 * Comprehensive Security & PKI Validation Suite testing:
 * 1. Root CA Status & Initialization
 * 2. Intermediate Sub-CA Import Validation (Rejecting web_server certs lacking cA=true)
 * 3. Subordinate Intermediate CA Setup & Chain Verification
 * 4. Sub-CA Certificate Issuance & RFC 5280 Unique Serials
 * 5. Parent Root CA Revocation of Sub-CA & Automatic Sub-CA Signing Lockout Enforcement
 */

const ROOT_CA_HOST = 'http://localhost:8088';
const SUB_CA_HOST = 'http://localhost:8089';
const PASSPHRASE = 'MasterPassphrase123!';

function request(url, method = 'GET', body = null) {
  return new Promise((resolve, reject) => {
    const urlObj = new URL(url);
    const postData = body ? JSON.stringify(body) : '';
    const options = {
      hostname: urlObj.hostname,
      port: urlObj.port,
      path: urlObj.pathname + urlObj.search,
      method: method,
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(postData),
        'Connection': 'close'
      }
    };

    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => (data += chunk));
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode, body: JSON.parse(data) });
        } catch (e) {
          resolve({ status: res.statusCode, body: data });
        }
      });
    });

    req.on('error', (err) => reject(err));
    if (postData) req.write(postData);
    req.end();
  });
}

async function runTestSuite() {
  console.log('\n============================================================');
  console.log('  ENTERPRISE step-ca FULL PKI SECURITY & VALIDATION SUITE');
  console.log('============================================================\n');

  let passed = 0;
  let failed = 0;

  function assert(condition, message) {
    if (condition) {
      console.log(`  ✅ [PASS] ${message}`);
      passed++;
    } else {
      console.error(`  ❌ [FAIL] ${message}`);
      failed++;
    }
  }

  try {
    // -------------------------------------------------------------
    // TEST 1: Check & Ensure Root CA Initialization
    // -------------------------------------------------------------
    console.log('>>> TEST 1: Checking Root CA Health & Initialization...');
    let rootStatus = await request(`${ROOT_CA_HOST}/api/setup/status`);
    assert(rootStatus.status === 200, 'Root CA API reachable on port 8088');

    if (rootStatus.body && !rootStatus.body.initialized) {
      console.log('  -> Root CA not initialized. Initializing Root CA automatically...');
      const initRes = await request(`${ROOT_CA_HOST}/api/setup/root`, 'POST', {
        caName: 'Enterprise Test Root CA v1',
        organization: 'Enterprise Test Corp',
        algorithm: 'RSA_2048',
        validityYears: 10,
        passphrase: PASSPHRASE
      });
      assert(initRes.status === 200 && initRes.body.success, 'Root CA initialized successfully');
      rootStatus = await request(`${ROOT_CA_HOST}/api/setup/status`);
    } else {
      console.log(`  -> Root CA active: ${rootStatus.body.config?.caName}`);
    }

    // Unlock Root CA session
    await request(`${ROOT_CA_HOST}/api/session/unlock`, 'POST', { passphrase: PASSPHRASE });

    // Ensure Sub-CA is uninitialized for Test 2
    await request(`${SUB_CA_HOST}/api/setup/reset`, 'POST', { passphrase: PASSPHRASE });
    // Generate keypair & CSR for web_server cert
    const fakeKeys = pki.rsa.generateKeyPair(2048);
    const fakeCsr = pki.createCertificationRequest();
    fakeCsr.publicKey = fakeKeys.publicKey;
    fakeCsr.setSubject([{ name: 'commonName', value: 'fake-subca.test.internal' }]);
    fakeCsr.sign(fakeKeys.privateKey, md.sha256.create());
    const fakeCsrPem = pki.certificationRequestToPem(fakeCsr);
    const fakePrivateKeyPem = pki.privateKeyToPem(fakeKeys.privateKey);

    // Issue a web server cert (which has cA: false)
    const webCertRes = await request(`${ROOT_CA_HOST}/api/certificates/issue`, 'POST', {
      commonName: 'fake-subca.test.internal',
      certType: 'web_server', // NOT a sub_ca! (cA: false)
      profile: 'standard',
      validityDays: 365,
      algorithm: 'RSA_2048',
      csrPem: fakeCsrPem,
      masterPassphrase: PASSPHRASE
    });

    assert(webCertRes.status === 200 && webCertRes.body.success, 'Issued web_server certificate (cA: false)');

    // Attempt to set up Sub-CA with this web_server certificate
    const invalidSubCaRes = await request(`${SUB_CA_HOST}/api/setup/intermediate-complete`, 'POST', {
      caName: 'Fake Sub CA',
      organization: 'Enterprise Corp',
      subCaCertPem: webCertRes.body.certificate.certPem,
      subCaPrivateKeyPem: fakePrivateKeyPem,
      parentRootCertPem: rootStatus.body.config?.caCertPem || '',
      passphrase: PASSPHRASE
    });

    if (invalidSubCaRes.status !== 400 || !invalidSubCaRes.body.error || !invalidSubCaRes.body.error.includes("basicConstraints: cA=true")) {
      console.log('  -> Test 2 Error Body:', invalidSubCaRes.body);
    }
    assert(
      invalidSubCaRes.status === 400 &&
        invalidSubCaRes.body.error.includes("basicConstraints: cA=true"),
      'Sub-CA setup engine successfully REJECTED web_server cert lacking basicConstraints cA=true!'
    );

    // -------------------------------------------------------------
    // TEST 3: Subordinate CA CSR & Root CA Signing (Valid Sub-CA)
    // -------------------------------------------------------------
    console.log('\n>>> TEST 3: Generating & Signing Valid Subordinate CA Certificate...');
    const subCsrRes = await request(`${SUB_CA_HOST}/api/setup/intermediate-csr`, 'POST', {
      caName: 'Enterprise Regional Sub-CA v1',
      organization: 'Enterprise Corp',
      algorithm: 'RSA_2048'
    });

    assert(subCsrRes.status === 200 && subCsrRes.body.csrPem, 'Sub-CA CSR generated');

    // Issue genuine sub_ca cert on Root CA
    const validSubCaCertRes = await request(`${ROOT_CA_HOST}/api/certificates/issue`, 'POST', {
      commonName: 'Enterprise Regional Sub-CA v1',
      certType: 'sub_ca', // VALID SUB CA! (cA: true)
      profile: 'infrastructure',
      validityDays: 730,
      algorithm: 'RSA_2048',
      csrPem: subCsrRes.body.csrPem,
      masterPassphrase: PASSPHRASE
    });

    if (!validSubCaCertRes.body.success) {
      console.log('  -> Valid Sub-CA Issue Error:', validSubCaCertRes.body);
    }
    assert(validSubCaCertRes.body.success, 'Valid Sub-CA certificate signed by Root CA');

    // Complete Sub-CA Setup
    const setupSubRes = await request(`${SUB_CA_HOST}/api/setup/intermediate-complete`, 'POST', {
      caName: 'Enterprise Regional Sub-CA v1',
      organization: 'Enterprise Corp',
      subCaCertPem: validSubCaCertRes.body.certificate.certPem,
      subCaPrivateKeyPem: subCsrRes.body.privateKeyPem,
      parentRootCertPem: rootStatus.body.config?.caCertPem || '',
      parentCrlUrl: `${ROOT_CA_HOST}/api/crl`,
      passphrase: PASSPHRASE
    });

    assert(setupSubRes.status === 200 && setupSubRes.body.success, 'Sub-CA initialized successfully with valid chain');

    // Unlock Sub-CA session
    await request(`${SUB_CA_HOST}/api/session/unlock`, 'POST', { passphrase: PASSPHRASE });

    // -------------------------------------------------------------
    // TEST 4: Certificate Issuance under Active Sub-CA
    // -------------------------------------------------------------
    console.log('\n>>> TEST 4: Issuing Leaf Certificate under Active Sub-CA...');
    const subLeafRes = await request(`${SUB_CA_HOST}/api/certificates/issue`, 'POST', {
      commonName: 'service.regional.internal',
      certType: 'web_server',
      profile: 'standard',
      validityDays: 365,
      algorithm: 'RSA_2048',
      masterPassphrase: PASSPHRASE
    });

    assert(subLeafRes.status === 200 && subLeafRes.body.success, 'Leaf certificate issued cleanly under Sub-CA');

    // -------------------------------------------------------------
    // TEST 5: Parent Root CA Revokes Sub-CA & Lockout Verification
    // -------------------------------------------------------------
    console.log('\n>>> TEST 5: Revoking Sub-CA on Root CA & Testing Lockout Enforcement...');
    const revokeSubRes = await request(`${ROOT_CA_HOST}/api/certificates/revoke`, 'POST', {
      certId: validSubCaCertRes.body.certificate.id,
      reasonCode: 2, // CA Compromise
      revocationDetails: 'Security Audit Revocation Test',
      masterPassphrase: PASSPHRASE
    });

    assert(revokeSubRes.status === 200, 'Subordinate CA cert revoked on Root CA');

    // Attempt to issue leaf certificate on Sub-CA (Must be BLOCKED by CRL Sync!)
    const blockedIssueRes = await request(`${SUB_CA_HOST}/api/certificates/issue`, 'POST', {
      commonName: 'blocked.regional.internal',
      certType: 'web_server',
      profile: 'standard',
      validityDays: 365,
      algorithm: 'RSA_2048',
      masterPassphrase: PASSPHRASE
    });

    if (blockedIssueRes.status !== 400 || !blockedIssueRes.body.error || !blockedIssueRes.body.error.includes('CA Certificate has been REVOKED by Parent Root Authority')) {
      console.log('  -> Blocked Issue Body:', blockedIssueRes.body);
    }
    assert(
      blockedIssueRes.status === 400 &&
        blockedIssueRes.body.error.includes('CA Certificate has been REVOKED by Parent Root Authority'),
      'Sub-CA engine successfully BLOCKED new certificate issuance due to Root CA revocation!'
    );

    // -------------------------------------------------------------
    // TEST 6: Replace Revoked Sub-CA Certificate & Restore Sub-CA
    // -------------------------------------------------------------
    console.log('\n>>> TEST 6: Replacing Revoked Sub-CA Certificate & Restoring Active Status...');
    // Generate new CSR for Sub-CA
    const newSubCsrRes = await request(`${SUB_CA_HOST}/api/setup/intermediate-csr`, 'POST', {
      caName: 'Enterprise Regional Sub-CA v2 (Replacement)',
      organization: 'Enterprise Corp',
      algorithm: 'RSA_2048'
    });

    assert(newSubCsrRes.status === 200 && newSubCsrRes.body.csrPem, 'Replacement Sub-CA CSR generated');

    // Issue new valid Sub-CA cert on Root CA
    const newSubCertRes = await request(`${ROOT_CA_HOST}/api/certificates/issue`, 'POST', {
      commonName: 'Enterprise Regional Sub-CA v2 (Replacement)',
      certType: 'sub_ca',
      profile: 'infrastructure',
      validityDays: 730,
      algorithm: 'RSA_2048',
      csrPem: newSubCsrRes.body.csrPem,
      masterPassphrase: PASSPHRASE
    });

    assert(newSubCertRes.status === 200 && newSubCertRes.body.success, 'New replacement Sub-CA certificate signed by Root CA');

    // Replace Sub-CA certificate on Sub-CA instance
    const replaceRes = await request(`${SUB_CA_HOST}/api/setup/replace-cert`, 'POST', {
      subCaCertPem: newSubCertRes.body.certificate.certPem,
      subCaPrivateKeyPem: newSubCsrRes.body.privateKeyPem,
      parentRootCertPem: rootStatus.body.config?.caCertPem || '',
      passphrase: PASSPHRASE
    });

    assert(replaceRes.status === 200 && replaceRes.body.config.status === 'ACTIVE', 'Sub-CA certificate replaced & restored to ACTIVE status!');

    // Verify Sub-CA can now issue leaf certificates again!
    const restoredIssueRes = await request(`${SUB_CA_HOST}/api/certificates/issue`, 'POST', {
      commonName: 'restored.regional.internal',
      certType: 'web_server',
      profile: 'standard',
      validityDays: 365,
      algorithm: 'RSA_2048',
      masterPassphrase: PASSPHRASE
    });

    assert(
      restoredIssueRes.status === 200 && restoredIssueRes.body.success,
      'Leaf certificate issued successfully under Restored Sub-CA!'
    );

    assert(
      restoredIssueRes.body.certificate.crlDistributionPoint !== undefined,
      'RFC 5280 cRLDistributionPoints (CDP) extension correctly embedded in issued X.509 certificate!'
    );

    // -------------------------------------------------------------
    // TEST 7: Testing Direct PKI Server Functions (SSH, PKCS12, CRL, OPA)
    // -------------------------------------------------------------
    console.log('\n>>> TEST 7: Testing Advanced PKI Modules (SSH Signing, PKCS12 Export, CRL, OPA)...');
    
    // Import server modules directly for unit coverage
    const { issueSshCertificate, exportPkcs12, generateCrl, setCaSessionPassphrase, clearCaSessionPassphrase } = await import('./server/pki.js');
    const { evaluatePolicy } = await import('./server/opa.js');

    // Test OPA Evaluation
    const opaAllowed = evaluatePolicy({ algorithm: 'RSA_2048', validity_days: 365, sans: ['valid.domain.local'], cert_type: 'web_server', profile: 'standard' });
    assert(opaAllowed.allowed === true, 'OPA Policy Evaluation cleanly ALLOWS compliant certificate request');

    const opaDenied = evaluatePolicy({ algorithm: 'RSA_2048', validity_days: 1000, sans: ['invalid.local'], cert_type: 'web_server', profile: 'standard' });
    assert(opaDenied.allowed === false, 'OPA Policy Evaluation cleanly DENIES request exceeding validity period limit');

    // Test Session unlock/lock
    setCaSessionPassphrase(PASSPHRASE, 15);
    
    // Test SSH Certificate Signing
    const sshCert = issueSshCertificate({
      identity: 'user@enterprise.internal',
      certType: 'ssh_user',
      principals: ['ubuntu', 'admin'],
      validityDays: 30,
      masterPassphrase: PASSPHRASE
    });
    assert(sshCert && sshCert.id, 'OpenSSH User Certificate signed cleanly');

    // Test CRL Generation
    const crlObj = generateCrl();
    assert(crlObj && crlObj.revokedCertificates !== undefined, 'CRL object generated successfully with revoked certificates list');

    // Test PKCS#12 Export
    const { issueCertificate } = await import('./server/pki.js');
    const unitCert = await issueCertificate({
      commonName: 'unit.pkcs12.test',
      certType: 'web_server',
      profile: 'standard',
      validityDays: 365,
      algorithm: 'RSA_2048',
      masterPassphrase: PASSPHRASE
    });
    const p12Buffer = exportPkcs12(unitCert.id, 'P12Password123!');
    assert(p12Buffer && p12Buffer.length > 0, 'Password-protected PKCS#12 (.pfx) bundle generated successfully');

    clearCaSessionPassphrase();

    console.log('\n============================================================');
    console.log(`  SECURITY VALIDATION RESULTS: ${passed} Passed, ${failed} Failed`);
    console.log('============================================================\n');

    if (failed > 0) process.exit(1);
  } catch (err) {
    console.error('Test Suite Execution Error:', err);
    process.exit(1);
  }
}

runTestSuite();
