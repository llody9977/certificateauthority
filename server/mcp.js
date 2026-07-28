import {
  getRevocationStatusWithTtlCache,
  syncParentCrlAndCheckRevocation,
  issueCertificate,
  createCsr
} from './pki.js';
import { evaluatePolicy } from './opa.js';
import { getDb, addAuditLog } from './db.js';

export const MCP_TOOLS_MANIFEST = [
  {
    name: 'check_ca_status',
    description: 'Query current CA health, initialization status, status (ACTIVE/REVOKED), and active certificate count.',
    inputSchema: {
      type: 'object',
      properties: {
        forceRefresh: { type: 'boolean', description: 'Force parent CRL sync refresh.' }
      }
    }
  },
  {
    name: 'list_certificates',
    description: 'Search and filter active and revoked certificates in the CA inventory.',
    inputSchema: {
      type: 'object',
      properties: {
        query: { type: 'string', description: 'Search term matching CommonName, Serial Number, or Fingerprint.' },
        status: { type: 'string', enum: ['ALL', 'ACTIVE', 'REVOKED'], description: 'Filter by certificate status.' },
        certType: { type: 'string', description: 'Filter by certificate type (e.g. web_server, client_auth, sub_ca).' }
      }
    }
  },
  {
    name: 'evaluate_opa_policy',
    description: 'Simulate and evaluate an X.509 or SSH credential request against OPA compliance rules.',
    inputSchema: {
      type: 'object',
      required: ['algorithm', 'validityDays', 'certType'],
      properties: {
        algorithm: { type: 'string', description: 'Signature algorithm (e.g. RSA_2048, RSA_4096, ECDSA_P256).' },
        validityDays: { type: 'integer', description: 'Requested validity period in days.' },
        certType: { type: 'string', description: 'Certificate type (e.g. web_server, client_auth, mtls).' },
        profile: { type: 'string', description: 'Profile tier (e.g. standard, short_lived, infrastructure).' },
        sans: { type: 'array', items: { type: 'string' }, description: 'Subject Alternative Names (SANs).' },
        commonName: { type: 'string', description: 'Subject Common Name (CN).' }
      }
    }
  },
  {
    name: 'issue_certificate',
    description: 'Request and issue a signed X.509 certificate under OPA policy governance rules.',
    inputSchema: {
      type: 'object',
      required: ['commonName'],
      properties: {
        commonName: { type: 'string', description: 'Common Name (CN) for the certificate.' },
        certType: { type: 'string', default: 'web_server', description: 'Certificate type.' },
        profile: { type: 'string', default: 'standard', description: 'Certificate profile.' },
        validityDays: { type: 'integer', default: 365, description: 'Validity duration in days.' },
        algorithm: { type: 'string', default: 'RSA_2048', description: 'Key algorithm.' },
        sans: { type: 'array', items: { type: 'string' }, description: 'Subject Alternative Names.' },
        organization: { type: 'string', description: 'Organization name.' },
        country: { type: 'string', description: 'Country code.' }
      }
    }
  },
  {
    name: 'check_revocation',
    description: 'Check 5-minute TTL cached revocation status for a given certificate serial number.',
    inputSchema: {
      type: 'object',
      required: ['serialNumber'],
      properties: {
        serialNumber: { type: 'string', description: 'Certificate decimal or hex serial number.' }
      }
    }
  }
];

export async function handleMcpRequest(jsonRpcReq, metaContext = {}) {
  const { id, method, params } = jsonRpcReq;

  if (method === 'tools/list' || method === 'mcp_tools/list') {
    return {
      jsonrpc: '2.0',
      id,
      result: { tools: MCP_TOOLS_MANIFEST }
    };
  }

  if (method === 'tools/call' || method === 'mcp_tools/call') {
    const name = params?.name;
    const args = params?.arguments || params?.args || {};

    try {
      let contentResult;

      if (name === 'check_ca_status') {
        const syncStatus = await syncParentCrlAndCheckRevocation(Boolean(args.forceRefresh));
        const db = getDb();
        contentResult = {
          caName: db.config?.caName || 'Uninitialized CA',
          caType: db.config?.type || 'none',
          status: db.config?.status || 'UNINITIALIZED',
          serialNumber: db.config?.serialNumber || '',
          fingerprint: db.config?.fingerprint || '',
          parentCrlUrl: db.config?.parentCrlUrl || '',
          crlDistributionPoint: db.config?.crlDistributionPoint || '/api/crl',
          activeCertCount: db.certificates.filter(c => c.status === 'ACTIVE').length,
          totalCertCount: db.certificates.length,
          syncStatus
        };
      } else if (name === 'list_certificates') {
        const db = getDb();
        let certs = [...db.certificates];
        if (args.status && args.status !== 'ALL') {
          certs = certs.filter(c => c.status === args.status);
        }
        if (args.certType) {
          certs = certs.filter(c => c.certType === args.certType);
        }
        if (args.query) {
          const q = args.query.toLowerCase();
          certs = certs.filter(c =>
            (c.commonName && c.commonName.toLowerCase().includes(q)) ||
            (c.serialNumber && c.serialNumber.includes(q)) ||
            (c.fingerprint && c.fingerprint.toLowerCase().includes(q))
          );
        }
        contentResult = {
          count: certs.length,
          certificates: certs.slice(0, 20).map(c => ({
            id: c.id,
            serialNumber: c.serialNumber,
            commonName: c.commonName,
            certType: c.certType,
            status: c.status,
            validFrom: c.validFrom,
            validTo: c.validTo,
            fingerprint: c.fingerprint,
            crlDistributionPoint: c.crlDistributionPoint
          }))
        };
      } else if (name === 'evaluate_opa_policy') {
        const opaResult = evaluatePolicy({
          algorithm: args.algorithm || 'RSA_2048',
          cert_type: args.certType || 'web_server',
          profile: args.profile || 'standard',
          validity_days: parseInt(args.validityDays || 365),
          sans: args.sans || (args.commonName ? [args.commonName] : []),
          subject: { commonName: args.commonName || 'test', organization: 'Enterprise' }
        });
        contentResult = opaResult;
      } else if (name === 'issue_certificate') {
        const cert = await issueCertificate({
          commonName: args.commonName,
          certType: args.certType || 'web_server',
          profile: args.profile || 'standard',
          validityDays: parseInt(args.validityDays || 365),
          algorithm: args.algorithm || 'RSA_2048',
          sans: args.sans || [],
          organization: args.organization || 'Enterprise CA',
          country: args.country || 'US',
          masterPassphrase: args.masterPassphrase
        });

        addAuditLog('MCP_ISSUE_CERTIFICATE', metaContext.performedBy || 'mcp-agent', args.commonName, 'SUCCESS', {
          certId: cert.id,
          serialNumber: cert.serialNumber
        }, metaContext);

        contentResult = {
          success: true,
          certificateId: cert.id,
          serialNumber: cert.serialNumber,
          commonName: cert.commonName,
          status: cert.status,
          validTo: cert.validTo,
          certPem: cert.certPem,
          fingerprint: cert.fingerprint
        };
      } else if (name === 'check_revocation') {
        const status = getRevocationStatusWithTtlCache();
        const isRevoked = status.revokedSerials.has(args.serialNumber);
        contentResult = {
          serialNumber: args.serialNumber,
          caStatus: status.caStatus,
          isRevoked,
          status: isRevoked ? 'REVOKED' : 'ACTIVE',
          cached: status.cached,
          cacheAgeSeconds: status.cacheAgeSeconds
        };
      } else {
        throw new Error(`Tool '${name}' not recognized by MCP server.`);
      }

      return {
        jsonrpc: '2.0',
        id,
        result: {
          content: [
            {
              type: 'text',
              text: typeof contentResult === 'string' ? contentResult : JSON.stringify(contentResult, null, 2)
            }
          ],
          isError: false
        }
      };
    } catch (err) {
      return {
        jsonrpc: '2.0',
        id,
        error: {
          code: -32603,
          message: err.message
        }
      };
    }
  }

  return {
    jsonrpc: '2.0',
    id,
    error: {
      code: -32601,
      message: `Method '${method}' not found.`
    }
  };
}
