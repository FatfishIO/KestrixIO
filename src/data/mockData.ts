import { Team, Asset, Scan, Finding, Occurrence, StatusChange, AiOutput } from '../core/types';
import { computeSastFingerprint, computeSecretFingerprint, computeDependencyFingerprint } from '../core/fingerprint';
import { calculateRiskScore, calculateSlaDueDate } from '../core/scoring';

export const INITIAL_TEAMS: Team[] = [
  {
    id: 'team-core',
    name: 'Core Security & Platform',
    owners: ['test-core@kestrix.local'],
    createdAt: '2026-10-15T08:00:00Z',
  },
  {
    id: 'team-checkout',
    name: 'Payments & Checkout',
    owners: ['test-pay@kestrix.local'],
    createdAt: '2026-10-16T09:30:00Z',
  },
  {
    id: 'team-mobile',
    name: 'Mobile Client Apps',
    owners: ['test-mobile@kestrix.local'],
    createdAt: '2026-10-17T11:00:00Z',
  },
];

export const INITIAL_ASSETS: Asset[] = [
  {
    id: 'asset-auth-service',
    teamId: 'team-core',
    name: 'auth-gateway-service',
    repoUrl: 'https://github.com/kestrix-corp/auth-gateway-service',
    criticality: 1,
    internetFacing: true,
    environment: 'production',
    dataClass: 'pci_dss',
    createdAt: '2026-10-15T10:00:00Z',
  },
  {
    id: 'asset-payment-api',
    teamId: 'team-checkout',
    name: 'payment-processing-engine',
    repoUrl: 'https://github.com/kestrix-corp/payment-processing-engine',
    criticality: 1,
    internetFacing: true,
    environment: 'production',
    dataClass: 'pci_dss',
    createdAt: '2026-10-16T12:00:00Z',
  },
  {
    id: 'asset-internal-portal',
    teamId: 'team-core',
    name: 'ops-internal-portal',
    repoUrl: 'https://github.com/kestrix-corp/ops-internal-portal',
    criticality: 3,
    internetFacing: false,
    environment: 'staging',
    dataClass: 'internal',
    createdAt: '2026-10-17T14:20:00Z',
  },
];

// Helper to pre-calculate fingerprints
const sast1Fp = computeSastFingerprint(
  'javascript.express.security.audit.sqli',
  'src/routes/auth.ts',
  'const user = await db.query(`SELECT * FROM users WHERE email = \'${req.body.email}\'`);'
);

const secret1Res = computeSecretFingerprint(
  'aws-access-key-id',
  'deploy/production.env',
  'TEST_AWS_KEY_SAMPLE_7EXAMPLE'
);

const dep1Fp = computeDependencyFingerprint(
  'npm',
  'axios',
  'GHSA-42xw-2xvc-cx4y',
  'package.json'
);

const sast2Fp = computeSastFingerprint(
  'javascript.lang.security.audit.insecure-cookie',
  'src/middleware/session.ts',
  'res.cookie("session_id", id, { secure: false, httpOnly: false });'
);

const sast1Score = calculateRiskScore(
  {
    type: 'sast',
    cweCategory: 'CWE-89 SQL Injection',
    isProductionPath: true,
    ruleSeverity: 'ERROR',
    ruleConfidence: 'HIGH',
  },
  INITIAL_ASSETS[0]
);

const secret1Score = calculateRiskScore(
  {
    type: 'secret',
    secretActive: true,
    secretType: 'aws-access-key-id',
    isGitHistory: false,
  },
  INITIAL_ASSETS[0]
);

const dep1Score = calculateRiskScore(
  {
    type: 'dependency',
    inKev: true,
    reachable: true,
    epssScore: 0.88,
    cvssScore: 9.8,
  },
  INITIAL_ASSETS[1]
);

const sast2Score = calculateRiskScore(
  {
    type: 'sast',
    cweCategory: 'CWE-614 Insecure Cookie',
    isProductionPath: true,
    ruleSeverity: 'WARNING',
    ruleConfidence: 'MEDIUM',
  },
  INITIAL_ASSETS[2]
);

export const INITIAL_FINDINGS: Finding[] = [
  {
    id: 'f-sqli-auth',
    assetId: 'asset-auth-service',
    type: 'sast',
    fingerprint: sast1Fp,
    ruleOrVulnId: 'javascript.express.security.audit.sqli',
    title: 'SQL Injection in user login credential authentication',
    status: 'new',
    riskLevel: sast1Score.riskLevel,
    riskReasons: sast1Score.riskReasons,
    firstSeen: '2026-10-18T14:00:00Z',
    lastSeen: '2026-10-19T20:15:00Z',
    slaDue: calculateSlaDueDate(sast1Score.slaDays)?.toISOString() || null,
    reopened: false,
  },
  {
    id: 'f-sec-aws',
    assetId: 'asset-auth-service',
    type: 'secret',
    fingerprint: secret1Res.fingerprint,
    ruleOrVulnId: 'aws-access-key-id',
    title: 'AWS Access Key ID exposed in production deploy manifest',
    status: 'triaged',
    riskLevel: secret1Score.riskLevel,
    riskReasons: secret1Score.riskReasons,
    firstSeen: '2026-10-17T09:12:00Z',
    lastSeen: '2026-10-19T20:15:00Z',
    slaDue: calculateSlaDueDate(secret1Score.slaDays)?.toISOString() || null,
    reopened: false,
    secretHash: secret1Res.secretHash,
    secretMasked: secret1Res.secretMasked,
  },
  {
    id: 'f-dep-axios',
    assetId: 'asset-payment-api',
    type: 'dependency',
    fingerprint: dep1Fp,
    ruleOrVulnId: 'GHSA-42xw-2xvc-cx4y',
    title: 'Axios SSRF in proxy authentication header (CVE-2023-45857)',
    status: 'in_progress',
    riskLevel: dep1Score.riskLevel,
    riskReasons: dep1Score.riskReasons,
    firstSeen: '2026-10-16T11:00:00Z',
    lastSeen: '2026-10-19T18:30:00Z',
    slaDue: calculateSlaDueDate(dep1Score.slaDays)?.toISOString() || null,
    reopened: true, // Marked reopened from previous release
  },
  {
    id: 'f-sast-cookie',
    assetId: 'asset-internal-portal',
    type: 'sast',
    fingerprint: sast2Fp,
    ruleOrVulnId: 'javascript.lang.security.audit.insecure-cookie',
    title: 'Session Cookie missing Secure and HttpOnly flags',
    status: 'triaged',
    riskLevel: sast2Score.riskLevel,
    riskReasons: sast2Score.riskReasons,
    firstSeen: '2026-10-15T16:00:00Z',
    lastSeen: '2026-10-19T14:00:00Z',
    slaDue: calculateSlaDueDate(sast2Score.slaDays)?.toISOString() || null,
    reopened: false,
  },
];

export const INITIAL_OCCURRENCES: Occurrence[] = [
  {
    id: 'occ-1',
    findingId: 'f-sqli-auth',
    scanId: 'scan-semgrep-01',
    filePath: 'src/routes/auth.ts',
    lineStart: 42,
    lineEnd: 46,
    snippetHash: 'sha256-43e91a0f8...',
  },
  {
    id: 'occ-2',
    findingId: 'f-sec-aws',
    scanId: 'scan-gitleaks-01',
    filePath: 'deploy/production.env',
    lineStart: 14,
    lineEnd: 14,
  },
  {
    id: 'occ-3',
    findingId: 'f-dep-axios',
    scanId: 'scan-osv-01',
    filePath: 'package.json',
    lineStart: 28,
    lineEnd: 28,
  },
  {
    id: 'occ-4',
    findingId: 'f-sast-cookie',
    scanId: 'scan-semgrep-01',
    filePath: 'src/middleware/session.ts',
    lineStart: 18,
    lineEnd: 22,
  },
];

export const INITIAL_STATUS_CHANGES: StatusChange[] = [
  {
    id: 'sc-seed-1',
    findingId: 'f-sec-aws',
    fromStatus: 'new',
    toStatus: 'triaged',
    actor: 'secops@kestrix.local',
    reason: 'Xác nhận secret AWS hợp lệ qua AWS IAM credential test. Cần rotate khẩn cấp.',
    changedAt: '2026-10-17T10:00:00Z',
  },
  {
    id: 'sc-seed-2',
    findingId: 'f-dep-axios',
    fromStatus: 'fixed',
    toStatus: 'triaged',
    actor: 'system',
    reason: 'Reappeared in scan scan-osv-01 (commit 8f24a1b). Marked reopened.',
    changedAt: '2026-10-18T11:00:00Z',
  },
  {
    id: 'sc-seed-3',
    findingId: 'f-dep-axios',
    fromStatus: 'triaged',
    toStatus: 'in_progress',
    actor: 'test-pay@kestrix.local',
    reason: 'Đang nâng cấp version axios lên 1.7.4 trong PR #89.',
    changedAt: '2026-10-19T08:30:00Z',
  },
];

export const INITIAL_SCANS: Scan[] = [
  {
    id: 'scan-semgrep-01',
    assetId: 'asset-auth-service',
    commitSha: '9b3f02e48231',
    branch: 'main',
    scanner: 'semgrep',
    scannerVersion: '1.92.0',
    rulesVersion: 'p/security-audit-2026.10',
    status: 'completed',
    findingsCount: 2,
    startedAt: '2026-10-19T20:10:00Z',
    completedAt: '2026-10-19T20:15:00Z',
  },
  {
    id: 'scan-gitleaks-01',
    assetId: 'asset-auth-service',
    commitSha: '9b3f02e48231',
    branch: 'main',
    scanner: 'gitleaks',
    scannerVersion: '8.21.0',
    rulesVersion: 'gitleaks-default-rules-v8',
    status: 'completed',
    findingsCount: 1,
    startedAt: '2026-10-19T20:12:00Z',
    completedAt: '2026-10-19T20:14:00Z',
  },
  {
    id: 'scan-osv-01',
    assetId: 'asset-payment-api',
    commitSha: '8f24a1b0213d',
    branch: 'main',
    scanner: 'osv-scanner',
    scannerVersion: '1.8.2',
    rulesVersion: 'osv-db-2026-10-19',
    status: 'completed',
    findingsCount: 1,
    startedAt: '2026-10-19T18:25:00Z',
    completedAt: '2026-10-19T18:30:00Z',
  },
];

export const INITIAL_VULNERABILITIES = [
  {
    id: 'GHSA-42xw-2xvc-cx4y',
    aliases: ['CVE-2023-45857'],
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N',
    cvssScore: 6.5,
    cvssSource: 'CNA (GitHub Advisory)',
    epss: 0.8812,
    kev: true,
    ssvc: 'Act',
    fixedVersions: ['1.6.0', '1.7.4'],
    fetchedAt: '2026-10-22T00:00:00Z',
  },
  {
    id: 'CVE-2024-29041',
    aliases: ['GHSA-rv95-896h-c2vc'],
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
    cvssScore: 6.1,
    cvssSource: 'CNA (OpenJS Foundation)',
    epss: 0.142,
    kev: false,
    ssvc: 'Attend',
    fixedVersions: ['4.19.2'],
    fetchedAt: '2026-10-22T00:00:00Z',
  },
];

