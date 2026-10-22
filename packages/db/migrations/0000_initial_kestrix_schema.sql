-- Kestrix Initial PostgreSQL Schema Migration (0000_initial_kestrix_schema.sql)
-- Generated via drizzle-kit / aligned 100% with docs/ERD.md

CREATE TABLE IF NOT EXISTS "teams" (
  "id" text PRIMARY KEY NOT NULL,
  "name" text NOT NULL,
  "owners" jsonb DEFAULT '[]'::jsonb NOT NULL,
  "created_at" timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE IF NOT EXISTS "assets" (
  "id" text PRIMARY KEY NOT NULL,
  "team_id" text NOT NULL REFERENCES "teams"("id") ON DELETE RESTRICT,
  "name" text NOT NULL,
  "repo_url" text NOT NULL,
  "criticality" integer DEFAULT 2 NOT NULL,
  "internet_facing" boolean DEFAULT false NOT NULL,
  "environment" text DEFAULT 'production' NOT NULL,
  "data_class" text DEFAULT 'internal' NOT NULL,
  "sandbox_tests_enabled" boolean DEFAULT false NOT NULL,
  "created_at" timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE IF NOT EXISTS "scans" (
  "id" text PRIMARY KEY NOT NULL,
  "asset_id" text NOT NULL REFERENCES "assets"("id") ON DELETE CASCADE,
  "commit_sha" text NOT NULL,
  "branch" text DEFAULT 'main' NOT NULL,
  "scanner" text NOT NULL,
  "scanner_version" text NOT NULL,
  "rules_version" text NOT NULL,
  "status" text DEFAULT 'queued' NOT NULL,
  "findings_count" integer DEFAULT 0 NOT NULL,
  "started_at" timestamp with time zone,
  "completed_at" timestamp with time zone
);

-- Core Findings Table
-- Rule #1: Raw secret is NEVER stored. Only secret_hash (SHA-256) and secret_masked (last 4 chars).
CREATE TABLE IF NOT EXISTS "findings" (
  "id" text PRIMARY KEY NOT NULL,
  "asset_id" text NOT NULL REFERENCES "assets"("id") ON DELETE CASCADE,
  "type" text NOT NULL,
  "fingerprint" text NOT NULL,
  "rule_or_vuln_id" text NOT NULL,
  "title" text NOT NULL,
  "status" text DEFAULT 'new' NOT NULL,
  "risk_level" text DEFAULT 'P3' NOT NULL,
  "risk_reasons" jsonb DEFAULT '[]'::jsonb NOT NULL,
  "first_seen" timestamp with time zone DEFAULT now() NOT NULL,
  "last_seen" timestamp with time zone DEFAULT now() NOT NULL,
  "sla_due" timestamp with time zone,
  "reopened" boolean DEFAULT false NOT NULL,
  "secret_hash" text,
  "secret_masked" text
);

CREATE UNIQUE INDEX IF NOT EXISTS "idx_findings_asset_fingerprint"
  ON "findings" ("asset_id", "fingerprint");

CREATE TABLE IF NOT EXISTS "occurrences" (
  "id" text PRIMARY KEY NOT NULL,
  "finding_id" text NOT NULL REFERENCES "findings"("id") ON DELETE CASCADE,
  "scan_id" text NOT NULL REFERENCES "scans"("id") ON DELETE CASCADE,
  "file_path" text NOT NULL,
  "line_start" integer,
  "line_end" integer,
  "snippet_hash" text
);

CREATE TABLE IF NOT EXISTS "vulnerabilities" (
  "id" text PRIMARY KEY NOT NULL,
  "aliases" jsonb DEFAULT '[]'::jsonb NOT NULL,
  "cvss_vector" text,
  "cvss_score" real,
  "cvss_source" text,
  "epss" real,
  "kev" boolean DEFAULT false NOT NULL,
  "ssvc" text,
  "fixed_versions" jsonb DEFAULT '[]'::jsonb NOT NULL,
  "fetched_at" timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE IF NOT EXISTS "status_changes" (
  "id" text PRIMARY KEY NOT NULL,
  "finding_id" text NOT NULL REFERENCES "findings"("id") ON DELETE CASCADE,
  "from_status" text NOT NULL,
  "to_status" text NOT NULL,
  "actor" text NOT NULL,
  "reason" text NOT NULL,
  "expires_at" timestamp with time zone,
  "changed_at" timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE IF NOT EXISTS "ai_outputs" (
  "id" text PRIMARY KEY NOT NULL,
  "finding_id" text NOT NULL REFERENCES "findings"("id") ON DELETE CASCADE,
  "kind" text NOT NULL,
  "model" text NOT NULL,
  "prompt_version" text NOT NULL,
  "input_hash" text NOT NULL,
  "output_json" jsonb NOT NULL,
  "confidence" real,
  "reviewed_by" text,
  "created_at" timestamp with time zone DEFAULT now() NOT NULL
);
