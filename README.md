# Certificate Authority Platform

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![OCI Container Image](https://img.shields.io/badge/Container-OCI%20Single%20Image-emerald)](Dockerfile)
[![RFC 5280 Compliance](https://img.shields.io/badge/RFC-5280%20X.509%20v3-indigo)](https://datatracker.ietf.org/doc/html/rfc5280)
[![OPA Governed](https://img.shields.io/badge/Governance-Open%20Policy%20Agent-amber)](https://www.openpolicyagent.org/)

A full-featured, secure Certificate Authority (CA) platform packaged as a **single OCI compliant container image**. Features **OPA policy governance**, **RFC 5280 compliance**, **OpenSSH CA signing**, **ACME protocol support**, **password-protected PKCS#12 export**, **5-minute TTL revocation caching**, and multi-container deployment capabilities for Docker, Kubernetes, OpenShift, AWS ECS, Azure Container Instances, and GCP Cloud Run.

---

## 🙏 Acknowledgements & Credits

The underlying PKI architecture, certificate issuance principles, and cryptographic engine design are powered by and inspired by **[Smallstep step-ca](https://smallstep.com/docs/step-ca/)**. We gratefully acknowledge the Smallstep open-source team and community for pioneering modern open-source certificate authority and public key infrastructure engineering.

---

## 📜 RFC Specifications Compliance Summary

The platform strictly adheres to official Internet Engineering Task Force (IETF) Request for Comments (RFC) standards and Public Key Infrastructure (PKI) specifications:

| RFC Specification | Standard Name | Implementation & Compliance Details |
| :--- | :--- | :--- |
| **RFC 5280** | Internet X.509 Public Key Infrastructure Certificate & CRL Profile | Enforces X.509 v3 extension profiles (`BasicConstraints`, `KeyUsage`, `ExtKeyUsage`, `SKI`, `AKI`), RFC 5280 unique 64-to-128-bit positive integer serial numbers, `cRLDistributionPoints` (CDP OID `2.5.29.31`) embedding, and RFC 5280 revocation reason codes. |
| **RFC 2986 / PKCS #10** | Certification Request Syntax Specification | Parses and verifies PKCS#10 Certificate Signing Requests (CSRs), verifies public key cryptography signatures, and extracts SAN extensions. |
| **RFC 8555** | Automatic Certificate Management Environment (ACME Protocol) | Exposes ACME directory endpoints (`/api/acme/directory`) for automated 90-day short-lived TLS client certificate issuance. |
| **RFC 4253 / RFC 8017** | OpenSSH Certificate Architecture | Implements OpenSSH User (`ssh-rsa-cert-v01@openssh.com`) and Host Certificate Authorities, scoping short-lived SSH principals. |
| **PKCS #12 / RFC 7292** | Personal Information Exchange Syntax Standard | Supports password-protected `.pfx` / `.p12` binary bundle exports utilizing TripleDES / AES key encryption for secure client certificate transport. |

---

## 🛡️ Security Hardening & PKI Best Practices

### 1. Cryptographic Private Key Hardening
- **At-Rest Private Key Encryption**: All CA private keys are encrypted using **AES-256-GCM authenticated encryption** combined with **PBKDF2 key derivation** (100,000 iterations) and 16-byte random salts.
- **Zero Key Leakage**: Private key PEM payloads are stripped from all public REST API read responses.
- **Approved Algorithms**: RSA 2048-bit, RSA 4096-bit, ECDSA P-256 (NIST), ECDSA P-384, and Ed25519.

### 2. OPA Policy Governance & Parameter Locking
- **Form-Based Rego Compiler**: Administrators configure governance policies through a visual UI form. The engine compiles these rules into Open Policy Agent (OPA) Rego policy code.
- **Strict Parameter Scoping**: Certificate issuance requests are evaluated against OPA policies before signing. Users cannot manually bypass algorithm restrictions, validity period caps per profile, or wildcard domain rules.

### 3. X.509 v3 Extension Guard & Sub-CA Validation
- **`basicConstraints: cA=true` Guard**: The setup engine validates all imported Subordinate CA certificates. Attempting to initialize an Intermediate CA with an end-entity certificate (e.g. `web_server`, `client_auth`) is rejected.
- **`keyUsage: keyCertSign` Requirement**: Ensures only valid certificate signing authorities are imported.

### 4. Cross-Container Revocation Lockout & Chain Integrity
- **Multi-Host Parent CRL Sync**: Subordinate CAs automatically query Parent Root CA CRL endpoints (`http://root-ca:3001/api/crl` or custom URLs).
- **Sub-CA Signing Lockdown**: If a Root CA revokes a Subordinate CA certificate, the Sub-CA engine immediately locks down signing and rejects any new certificate issuance.
- **Revocation Inheritance**: When a Sub-CA is replaced, certificates issued under the old revoked Sub-CA remain permanently marked as `CHAIN_REVOKED` / `UNTRUSTED`.

### 5. High-Performance 5-Minute TTL Revocation Caching
- **DB/Network Optimization**: Revocation status queries are cached in memory with a 5-minute Time-To-Live (300,000 ms).
- **Instant Event Invalidation**: Revocation events immediately purge the cache, ensuring revocations propagate without delay.

### 6. CA Session Auto-Locking
- Temporary in-memory key caching allows administrators to authorize signing sessions for 15 minutes, 1 hour, or 4 hours without storing unencrypted keys on disk.

### 7. Immutable Audit Trail & Preservation Guarantee
- Every CA setup, certificate issuance, revocation, OPA violation, session unlock, and CA reset writes an immutable entry to `db.auditLogs`.
- **CA Reset Guarantee**: Resetting a CA configuration clears instance certificate state but **PERMANENTLY PRESERVES all historical Audit Logs** for compliance and forensic auditing.

---

## 📦 Container Deployment Instructions

The platform is packaged as a standard, multi-stage OCI container image containing both the Express backend engine and compiled React frontend assets.

### 1. Build Production Container Image

```bash
docker build -t certificateauthority:latest .
```

---

### 2. Run Root CA Container Instance

Run an isolated Root CA container binding to host port `8088` with a persistent storage volume:

```bash
docker run -d \
  --name root-ca-instance \
  --restart unless-stopped \
  -p 8088:3001 \
  -v root_ca_data:/app/data \
  certificateauthority:latest
```

---

### 3. Run Intermediate Subordinate CA Container Instance

Run a Subordinate CA container binding to host port `8089` pointing to the Parent Root CA for CRL revocation sync:

```bash
docker run -d \
  --name intermediate-ca-instance \
  --restart unless-stopped \
  -p 8089:3001 \
  -v sub_ca_data:/app/data \
  certificateauthority:latest
```

---

### 4. Kubernetes (k8s) / OpenShift Deployment Manifest Example

Deploy using `PersistentVolumeClaim` and `Deployment`:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ca-root-instance
  namespace: pki-infrastructure
spec:
  replicas: 1
  selector:
    matchLabels:
      app: ca-root-instance
  template:
    metadata:
      labels:
        app: ca-root-instance
    spec:
      containers:
      - name: ca-engine
        image: certificateauthority:latest
        ports:
        - containerPort: 3001
        volumeMounts:
        - mountPath: /app/data
          name: ca-storage
        readinessProbe:
          httpGet:
            path: /api/setup/status
            port: 3001
          initialDelaySeconds: 5
          periodSeconds: 10
      volumes:
      - name: ca-storage
        persistentVolumeClaim:
          claimName: root-ca-pvc
---
apiVersion: v1
kind: Service
metadata:
  name: root-ca-service
  namespace: pki-infrastructure
spec:
  type: ClusterIP
  ports:
  - port: 8088
    targetPort: 3001
  selector:
    app: ca-root-instance
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
├── Dockerfile           # Multi-stage OCI container image definition
└── test_ca_suite.js     # Self-contained 14-point automated test runner
```

---

## 📄 License
Released under the [MIT License](LICENSE).
