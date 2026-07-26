# Certificate Authority Platform

[![CI Pipeline](https://github.com/llody9977/certificateauthority/actions/workflows/ci.yml/badge.svg)](https://github.com/llody9977/certificateauthority/actions/workflows/ci.yml)
[![CodeQL Analysis](https://github.com/llody9977/certificateauthority/actions/workflows/codeql.yml/badge.svg)](https://github.com/llody9977/certificateauthority/actions/workflows/codeql.yml)
[![Release Security Scan](https://github.com/llody9977/certificateauthority/actions/workflows/release-security-scan.yml/badge.svg)](https://github.com/llody9977/certificateauthority/actions/workflows/release-security-scan.yml)
[![GitHub Release](https://img.shields.io/github/v/release/llody9977/certificateauthority?color=blue&logo=github)](https://github.com/llody9977/certificateauthority/releases)

## 💡 Why This Web CA Was Created

When looking for a Certificate Authority (CA) platform with robust capabilities comparable to **Microsoft Active Directory Certificate Services (AD CS / Windows CA)**, traditional solutions often feel heavy, resource-intensive, and tied to specific infrastructure ecosystems.

In search of a lightweight, modern alternative, **Smallstep `step-ca`** stood out as an excellent, fast, and cryptographically sound PKI engine. However, `step-ca` out-of-the-box is primarily a command-line interface (CLI) tool. It lacks a native Web UI, visual AD CS-style setup wizards, form-driven policy governance, interactive trust chain inspection, visual audit trail management, and web-based certificate operations.

This web application was created to bridge that gap: combining the lightweight cryptographic engine principles of `step-ca` with an intuitive web interface, Open Policy Agent (OPA) governance, visual audit logging, and streamlined certificate lifecycle operations.

---

## 🙏 Acknowledgements & Credits

The underlying PKI architecture, certificate signing workflows, and cryptographic concepts are powered by and inspired by **[Smallstep step-ca](https://smallstep.com/docs/step-ca/)**. We gratefully acknowledge the Smallstep open-source team for pioneering modern open-source certificate management.

---

## ✨ Features Implemented in Repository

- **AD CS-Style Setup Wizard**: Interactive Root CA initialization and single `.pem` bundle setup for Subordinate Intermediate CAs.
- **OPA Policy Governance**: Form-based policy builder and live simulator using Open Policy Agent (OPA) Rego rules.
- **X.509 v3 & OpenSSH Signing**: Standard X.509 web server/client certificate issuance plus OpenSSH User (`ssh-rsa-cert-v01@openssh.com`) and Host certificate signing.
- **Password-Protected PKCS#12 Export**: Secure `.pfx` / `.p12` bundle exports with TripleDES/AES key protection.
- **RFC 5280 Revocation Sync & Caching**: Automatic `cRLDistributionPoints` (CDP OID `2.5.29.31`) embedding, 5-minute TTL revocation status caching, and multi-host parent CRL sync.
- **Sub-CA Recovery & Revocation Lockout**: Automatic signing lockdown when a Sub-CA is revoked by its Parent CA; Sub-CA replacement option that preserves historical data; and CA decommission reset that **permanently preserves all Audit Logs**.
- **Visual Audit Trail & CSV Export**: Searchable audit logging tracking all setup, issuance, revocation, and session unlock events.
- **REST API & ACME Directory**: Exposes REST endpoints and ACME directory support (`/api/acme/directory`).

---

## 📜 RFC Specifications Compliance Summary

The platform strictly adheres to official Internet Engineering Task Force (IETF) Request for Comments (RFC) standards and Public Key Infrastructure (PKI) specifications:

| RFC Specification | Standard Name | Implementation & Compliance Details |
| :--- | :--- | :--- |
| **RFC 5280** | Internet X.509 Public Key Infrastructure Certificate & CRL Profile | Enforces X.509 v3 extension profiles (`BasicConstraints`, `KeyUsage`, `ExtKeyUsage`, `SKI`, `AKI`), RFC 5280 unique 64-to-128-bit positive integer serial numbers, `cRLDistributionPoints` (CDP OID `2.5.29.31`) embedding, and RFC 5280 revocation reason codes. |
| **RFC 2986 / PKCS #10** | Certification Request Syntax Specification | Parses and verifies PKCS#10 Certificate Signing Requests (CSRs), verifies public key cryptography signatures, and extracts SAN extensions. |
| **RFC 8555** | Automatic Certificate Management Environment (ACME Protocol) | Exposes ACME directory endpoints (`/api/acme/directory`) for automated short-lived TLS client certificate issuance. |
| **RFC 4253 / RFC 8017** | OpenSSH Certificate Architecture | Implements OpenSSH User (`ssh-rsa-cert-v01@openssh.com`) and Host Certificate Authorities, scoping short-lived SSH principals. |
| **PKCS #12 / RFC 7292** | Personal Information Exchange Syntax Standard | Supports password-protected `.pfx` / `.p12` binary bundle exports utilizing TripleDES / AES key encryption for secure client certificate transport. |

---

## 🛡️ Security Hardening & PKI Best Practices

### 1. Cryptographic Private Key Hardening
- **At-Rest Private Key Encryption**: All CA private keys are encrypted using **AES-256-GCM authenticated encryption** combined with **PBKDF2 key derivation** (100,000 iterations) and 16-byte random salts.
- **Zero Key Leakage**: Private key PEM payloads are stripped from all public REST API read responses.
- **Supported Cryptographic Algorithms**: RSA 2048-bit, RSA 4096-bit, ECDSA P-256 (NIST), ECDSA P-384, and Ed25519.

### 2. OPA Policy Governance & Parameter Locking
- **Form-Based Rego Compiler**: Administrators configure governance policies through a visual UI form. The engine compiles these rules into Open Policy Agent (OPA) Rego policy code.
- **Strict Parameter Scoping**: Certificate issuance requests are evaluated against OPA policies before signing.

### 3. X.509 v3 Extension Guard & Sub-CA Validation
- **`basicConstraints: cA=true` Guard**: The setup engine validates all imported Subordinate CA certificates. Attempting to initialize an Intermediate CA with an end-entity certificate (e.g. `web_server`, `client_auth`) is rejected.
- **`keyUsage: keyCertSign` Requirement**: Ensures only valid certificate signing authorities are imported.

### 4. Cross-Container Revocation Lockout & Chain Integrity
- **Multi-Host Parent CRL Sync**: Subordinate CAs automatically query Parent Root CA CRL endpoints (`/api/crl`).
- **Sub-CA Signing Lockdown**: If a Root CA revokes a Subordinate CA certificate, the Sub-CA engine immediately locks down signing and rejects any new certificate issuance.
- **Revocation Inheritance**: When a Sub-CA is replaced, certificates issued under the old revoked Sub-CA remain permanently marked as `CHAIN_REVOKED` / `UNTRUSTED`.

### 5. High-Performance 5-Minute TTL Revocation Caching
- **DB/Network Optimization**: Revocation status queries are cached in memory with a 5-minute Time-To-Live (300,000 ms).
- **Instant Event Invalidation**: Revocation events immediately purge the cache, ensuring revocations propagate without delay.

### 6. CA Session Auto-Locking
- Temporary in-memory key caching allows administrators to authorize signing sessions for 15 minutes, 1 hour, or 4 hours without storing unencrypted keys on disk.

### 7. Immutable Audit Trail & Preservation Guarantee
- Every CA setup, certificate issuance, revocation, OPA violation, session unlock, and CA reset writes an immutable entry to `db.auditLogs`.
- **CA Reset Guarantee**: Resetting a CA configuration clears instance certificate state but **PERMANENTLY PRESERVES all historical Audit Logs** for compliance and auditing.

---

## 📦 Container Deployment Instructions

The application is packaged as a standard multi-stage Docker container image (`Dockerfile`) containing both the Express backend server and compiled frontend static assets.

### 1. Build Container Image

```bash
docker build -t certificateauthority:latest .
```

### 2. Run Container Instance

Run an isolated container instance binding host port `8088` to container port `3001` with a persistent data volume mount:

```bash
docker run -d \
  --name ca-instance \
  --restart unless-stopped \
  -p 8088:3001 \
  -v ca_data:/app/data \
  certificateauthority:latest
```

---

## 🧪 Automated End-to-End Test Suite

Run the automated test runner to verify 14 end-to-end security & validation test scenarios:

```bash
node test_ca_suite.js
```

### Test Suite Output:
```text
============================================================
  FULL PKI SECURITY & VALIDATION SUITE
============================================================

>>> TEST 1: Checking Root CA Health & Initialization...
  ✅ [PASS] Root CA API reachable on port 8088
  ✅ [PASS] Root CA initialized successfully

>>> TEST 2: Testing Subordinate CA Import Extension Guard...
  ✅ [PASS] Issued web_server certificate (cA: false)
  ✅ [PASS] Sub-CA setup engine successfully REJECTED web_server cert lacking basicConstraints cA=true!

>>> TEST 3: Generating & Signing Valid Subordinate CA Certificate...
  ✅ [PASS] Sub-CA CSR generated
  ✅ [PASS] Valid Sub-CA certificate signed by Root CA
  ✅ [PASS] Sub-CA initialized successfully with valid chain

>>> TEST 4: Issuing Leaf Certificate under Active Sub-CA...
  ✅ [PASS] Leaf certificate issued cleanly under Sub-CA

>>> TEST 5: Revoking Sub-CA on Root CA & Testing Lockout Enforcement...
  ✅ [PASS] Subordinate CA cert revoked on Root CA
  ✅ [PASS] Sub-CA engine successfully BLOCKED new certificate issuance due to Root CA revocation!

>>> TEST 6: Replacing Revoked Sub-CA Certificate & Restoring Active Status...
  ✅ [PASS] Replacement Sub-CA CSR generated
  ✅ [PASS] New replacement Sub-CA certificate signed by Root CA
  ✅ [PASS] Sub-CA certificate replaced & restored to ACTIVE status!
  ✅ [PASS] Leaf certificate issued successfully under Restored Sub-CA!
  ✅ [PASS] RFC 5280 cRLDistributionPoints (CDP) extension correctly embedded in issued X.509 certificate!

============================================================
  SECURITY VALIDATION RESULTS: 14 Passed, 0 Failed
============================================================
```

---

## 📂 Architecture & Project Structure

```text
├── server/
│   ├── index.js         # Express REST API routes, OPA integration, & session unlock
│   ├── pki.js           # Core cryptographic engine, RFC 5280 logic, AES-GCM, & CRL sync
│   ├── db.js            # Persistent JSON file database & Audit Log trail
│   └── opa.js           # Form-driven OPA policy evaluation engine
├── src/
│   ├── components/
│   │   ├── Topbar.jsx        # Navigation, CA status pulse, unlock modal, & CA Recovery Hub
│   │   ├── SetupWizard.jsx   # AD CS setup wizard with single .pem bundle parser
│   │   ├── CertExplorer.jsx  # Cert directory, search, Trust Chain Inspector, & export/revoke
│   │   ├── CsrStudio.jsx     # CSR studio, X.509 issuance, & OpenSSH signing
│   │   ├── OpaManager.jsx    # Form-based OPA policy builder & simulator
│   │   └── AuditLogViewer.jsx# Searchable audit trail & CSV exporter
│   ├── index.css        # UI design tokens, typography, & controls
│   └── App.jsx          # Main application layout
├── Dockerfile           # Multi-stage Docker container image definition
└── test_ca_suite.js     # Self-contained 14-point automated test runner
```

---

## 📄 License
Released under the [MIT License](LICENSE).
