import {
  pgTable,
  uuid,
  varchar,
  text,
  smallint,
  boolean,
  integer,
  numeric,
  jsonb,
  timestamp,
  uniqueIndex,
} from 'drizzle-orm/pg-core';

/**
 * Kestrix Database Schema (Drizzle ORM + PostgreSQL)
 * Strict alignment with docs/ERD.md:
 * - Table and column names in DB: snake_case
 * - TypeScript inferred types: PascalCase
 */

export const teams = pgTable('teams', {
  id: uuid('id').defaultRandom().primaryKey(),
  name: varchar('name', { length: 100 }).notNull().unique(),
  owners: jsonb('owners').$type<string[]>().notNull().default([]),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
});

export const assets = pgTable('assets', {
  id: uuid('id').defaultRandom().primaryKey(),
  teamId: uuid('team_id')
    .notNull()
    .references(() => teams.id, { onDelete: 'restrict' }),
  name: varchar('name', { length: 150 }).notNull(),
  repoUrl: text('repo_url').notNull(),
  criticality: smallint('criticality').notNull(), // 1 to 4
  internetFacing: boolean('internet_facing').notNull().default(false),
  environment: varchar('environment', { length: 20 }).notNull(), // production, staging, development
  dataClass: varchar('data_class', { length: 20 }).notNull(), // pci_dss, pii, internal, public
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
});

export const scans = pgTable('scans', {
  id: uuid('id').defaultRandom().primaryKey(),
  assetId: uuid('asset_id')
    .notNull()
    .references(() => assets.id, { onDelete: 'cascade' }),
  commitSha: varchar('commit_sha', { length: 40 }).notNull(),
  branch: varchar('branch', { length: 100 }).notNull().default('main'),
  scanner: varchar('scanner', { length: 30 }).notNull(), // semgrep, gitleaks, osv-scanner
  scannerVersion: varchar('scanner_version', { length: 30 }).notNull(),
  rulesVersion: varchar('rules_version', { length: 30 }).notNull(),
  status: varchar('status', { length: 20 }).notNull(), // queued, running, completed, failed
  findingsCount: integer('findings_count').notNull().default(0),
  startedAt: timestamp('started_at', { withTimezone: true }),
  completedAt: timestamp('completed_at', { withTimezone: true }),
});

export const findings = pgTable(
  'findings',
  {
    id: uuid('id').defaultRandom().primaryKey(),
    assetId: uuid('asset_id')
      .notNull()
      .references(() => assets.id, { onDelete: 'cascade' }),
    type: varchar('type', { length: 20 }).notNull(), // sast, secret, dependency
    fingerprint: varchar('fingerprint', { length: 64 }).notNull(),
    ruleOrVulnId: varchar('rule_or_vuln_id', { length: 100 }).notNull(),
    title: varchar('title', { length: 255 }).notNull(),
    status: varchar('status', { length: 30 }).notNull(), // new, triaged, in_progress, fixed, false_positive, risk_accepted
    riskLevel: varchar('risk_level', { length: 5 }).notNull(), // P1, P2, P3, P4
    riskReasons: jsonb('risk_reasons').$type<string[]>().notNull().default([]),
    firstSeen: timestamp('first_seen', { withTimezone: true }).notNull().defaultNow(),
    lastSeen: timestamp('last_seen', { withTimezone: true }).notNull().defaultNow(),
    slaDue: timestamp('sla_due', { withTimezone: true }),
    reopened: boolean('reopened').notNull().default(false),
    // Security Rule #1: Never store raw secret, only SHA-256 hash and masked 4-char suffix
    secretHash: varchar('secret_hash', { length: 64 }),
    secretMasked: varchar('secret_masked', { length: 16 }),
  },
  (table) => ({
    assetFingerprintIdx: uniqueIndex('idx_findings_asset_fingerprint').on(
      table.assetId,
      table.fingerprint
    ),
  })
);

export const occurrences = pgTable('occurrences', {
  id: uuid('id').defaultRandom().primaryKey(),
  findingId: uuid('finding_id')
    .notNull()
    .references(() => findings.id, { onDelete: 'cascade' }),
  scanId: uuid('scan_id')
    .notNull()
    .references(() => scans.id, { onDelete: 'cascade' }),
  filePath: text('file_path').notNull(),
  lineStart: integer('line_start'),
  lineEnd: integer('line_end'),
  snippetHash: varchar('snippet_hash', { length: 64 }),
});

export const vulnerabilities = pgTable('vulnerabilities', {
  id: varchar('id', { length: 50 }).primaryKey(), // CVE-..., GHSA-..., OSV-...
  aliases: jsonb('aliases').$type<string[]>().notNull().default([]),
  cvssVector: varchar('cvss_vector', { length: 100 }),
  cvssScore: numeric('cvss_score', { precision: 3, scale: 1 }),
  cvssSource: varchar('cvss_source', { length: 50 }), // CNA, CVE.org, AI_PREDICTED
  epss: numeric('epss', { precision: 5, scale: 4 }),
  kev: boolean('kev').notNull().default(false),
  ssvc: varchar('ssvc', { length: 30 }), // Track, Attend, Act
  fixedVersions: jsonb('fixed_versions').$type<string[]>().notNull().default([]),
  fetchedAt: timestamp('fetched_at', { withTimezone: true }).notNull().defaultNow(),
});

export const statusChanges = pgTable('status_changes', {
  id: uuid('id').defaultRandom().primaryKey(),
  findingId: uuid('finding_id')
    .notNull()
    .references(() => findings.id, { onDelete: 'cascade' }),
  fromStatus: varchar('from_status', { length: 30 }).notNull(),
  toStatus: varchar('to_status', { length: 30 }).notNull(),
  actor: varchar('actor', { length: 100 }).notNull(),
  reason: text('reason').notNull(),
  expiresAt: timestamp('expires_at', { withTimezone: true }),
  changedAt: timestamp('changed_at', { withTimezone: true }).notNull().defaultNow(),
});

export const aiOutputs = pgTable('ai_outputs', {
  id: uuid('id').defaultRandom().primaryKey(),
  findingId: uuid('finding_id')
    .notNull()
    .references(() => findings.id, { onDelete: 'cascade' }),
  kind: varchar('kind', { length: 30 }).notNull(), // explain, triage, cvss, patch, advisory
  model: varchar('model', { length: 50 }).notNull(),
  promptVersion: varchar('prompt_version', { length: 20 }).notNull(),
  inputHash: varchar('input_hash', { length: 64 }).notNull(),
  outputJson: jsonb('output_json').$type<Record<string, unknown>>().notNull(),
  confidence: numeric('confidence', { precision: 3, scale: 2 }),
  reviewedBy: varchar('reviewed_by', { length: 100 }),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
});

export type DbTeam = typeof teams.$inferSelect;
export type DbAsset = typeof assets.$inferSelect;
export type DbScan = typeof scans.$inferSelect;
export type DbFinding = typeof findings.$inferSelect;
export type DbOccurrence = typeof occurrences.$inferSelect;
export type DbVulnerability = typeof vulnerabilities.$inferSelect;
export type DbStatusChange = typeof statusChanges.$inferSelect;
export type DbAiOutput = typeof aiOutputs.$inferSelect;
