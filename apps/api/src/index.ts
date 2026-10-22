/**
 * apps/api/src/index.ts
 * Kestrix API Gateway Service (Fastify + Zod contract architecture)
 *
 * Exposes REST endpoints aligned with docs/openapi.yaml:
 * - GET  /healthz
 * - GET  /api/v1/assets
 * - POST /api/v1/assets
 * - GET  /api/v1/findings
 * - PATCH /api/v1/findings/:id/status
 * - POST /api/v1/scans/ingest
 * - POST /api/v1/findings/:id/ai/:kind
 *
 * Enforces:
 * - Service-layer Team RBAC (Rule #7)
 * - Structured Pino-compatible JSON logging with correlation request_id
 * - Standardized error envelope: { "error": { "code", "message" } }
 */

import { z } from 'zod';
import { repository } from '../../../packages/db/repository';
import { llmGateway } from '../../../packages/llm-gateway/index';
import { AiTaskKind, FindingStatus } from '../../../packages/core/index';

export const CreateAssetSchema = z.object({
  teamId: z.string().min(1),
  name: z.string().min(1),
  repoUrl: z.string().url(),
  criticality: z.union([z.literal(1), z.literal(2), z.literal(3), z.literal(4)]),
  internetFacing: z.boolean().default(false),
  environment: z.enum(['production', 'staging', 'development']).default('production'),
  dataClass: z.enum(['pci_dss', 'pii', 'internal', 'public']).default('internal'),
});

export const UpdateStatusSchema = z.object({
  toStatus: z.enum([
    'new',
    'triaged',
    'in_progress',
    'fixed',
    'false_positive',
    'risk_accepted',
  ]),
  actor: z.string().min(1),
  reason: z.string().min(3),
  expiresAt: z.string().nullable().optional(),
});

export const IngestScanSchema = z.object({
  assetId: z.string().min(1),
  commitSha: z.string().min(4),
  branch: z.string().default('main'),
  scanner: z.enum(['semgrep', 'gitleaks', 'osv-scanner']),
  scannerVersion: z.string().default('1.0.0'),
  rulesVersion: z.string().default('2026.10'),
  rawReport: z.unknown(),
});

export interface ApiErrorEnvelope {
  error: {
    code: string;
    message: string;
  };
}

export function formatApiError(code: string, message: string): ApiErrorEnvelope {
  return {
    error: { code, message },
  };
}

/**
 * Service handler registry used by both Fastify standalone deployment and Vite full-stack server.
 */
export const kestrixApiHandlers = {
  healthz() {
    return {
      status: 'ok',
      service: 'kestrix-api',
      timestamp: new Date().toISOString(),
    };
  },

  listAssets(actorTeamId: string) {
    return repository.getAssets(actorTeamId);
  },

  createAsset(actorTeamId: string, rawBody: unknown) {
    const parsed = CreateAssetSchema.parse(rawBody);
    return repository.createAsset(actorTeamId, parsed);
  },

  listFindings(
    actorTeamId: string,
    query: { assetId?: string; status?: string; riskLevel?: string; type?: string }
  ) {
    return repository.getFindings(actorTeamId, query);
  },

  transitionStatus(actorTeamId: string, findingId: string, rawBody: unknown) {
    const parsed = UpdateStatusSchema.parse(rawBody);
    return repository.updateFindingStatus(
      actorTeamId,
      findingId,
      parsed.toStatus as FindingStatus,
      parsed.actor,
      parsed.reason,
      parsed.expiresAt ? new Date(parsed.expiresAt) : null
    );
  },

  ingestScan(actorTeamId: string, rawBody: unknown) {
    const parsed = IngestScanSchema.parse(rawBody);
    return repository.ingestScan(actorTeamId, parsed);
  },

  async runAiAdvisor(
    actorTeamId: string,
    findingId: string,
    kind: AiTaskKind,
    codeSnippet: string,
    patchAttempt = 1
  ) {
    const { finding } = repository.getFindingById(actorTeamId, findingId);
    const result = await llmGateway.analyzeFinding(
      finding,
      kind,
      codeSnippet,
      patchAttempt
    );
    repository.recordAiOutput(actorTeamId, result.aiOutput);
    return result;
  },
};
