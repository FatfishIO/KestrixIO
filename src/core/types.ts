/**
 * Kestrix Core Data Types & Enums
 * Pure domain definitions, strictly no I/O.
 */

export type FindingType = 'sast' | 'secret' | 'dependency';

export type FindingStatus =
  | 'new'
  | 'triaged'
  | 'in_progress'
  | 'fixed'
  | 'false_positive'
  | 'risk_accepted';

export type RiskLevel = 'P1' | 'P2' | 'P3' | 'P4';

export type Environment = 'production' | 'staging' | 'development';

export type DataClass = 'pci_dss' | 'pii' | 'internal' | 'public';

export type ScannerType = 'semgrep' | 'gitleaks' | 'osv-scanner';

export type AiTaskKind = 'explain' | 'triage' | 'cvss' | 'patch' | 'advisory';

export interface Team {
  id: string;
  name: string;
  owners: string[];
  createdAt: string;
}

export interface Asset {
  id: string;
  teamId: string;
  name: string;
  repoUrl: string;
  criticality: 1 | 2 | 3 | 4;
  internetFacing: boolean;
  environment: Environment;
  dataClass: DataClass;
  createdAt: string;
}

export interface Scan {
  id: string;
  assetId: string;
  commitSha: string;
  branch: string;
  scanner: ScannerType;
  scannerVersion: string;
  rulesVersion: string;
  status: 'queued' | 'running' | 'completed' | 'failed';
  findingsCount: number;
  startedAt?: string;
  completedAt?: string;
}

export interface Finding {
  id: string;
  assetId: string;
  type: FindingType;
  fingerprint: string;
  ruleOrVulnId: string;
  title: string;
  status: FindingStatus;
  riskLevel: RiskLevel;
  riskReasons: string[];
  firstSeen: string;
  lastSeen: string;
  slaDue: string | null;
  reopened: boolean;
  // Security rule #1: raw secret is NEVER saved
  secretHash?: string;
  secretMasked?: string;
}

export interface Occurrence {
  id: string;
  findingId: string;
  scanId: string;
  filePath: string;
  lineStart?: number;
  lineEnd?: number;
  snippetHash?: string;
}

export interface Vulnerability {
  id: string; // CVE, GHSA, OSV
  aliases: string[];
  cvssVector?: string;
  cvssScore?: number;
  cvssSource?: string;
  epss?: number;
  kev: boolean;
  ssvc?: string;
  fixedVersions: string[];
  fetchedAt: string;
}

export interface StatusChange {
  id: string;
  findingId: string;
  fromStatus: FindingStatus;
  toStatus: FindingStatus;
  actor: string;
  reason: string;
  expiresAt?: string | null;
  changedAt: string;
}

export interface AiOutput {
  id: string;
  findingId: string;
  kind: AiTaskKind;
  model: string;
  promptVersion: string;
  inputHash: string;
  outputJson: Record<string, unknown>;
  confidence?: number;
  reviewedBy?: string | null;
  createdAt: string;
}
