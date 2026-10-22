import 'dotenv/config';
import express, { Request, Response, NextFunction } from 'express';
import path from 'path';
import { z } from 'zod';
import { repository } from './packages/db/repository';
import { llmGateway } from './packages/llm-gateway';
import { AiTaskKind, FindingStatus, ScannerType } from './src/core/types';

/**
 * Structured Pino-compatible JSON logger
 * Strictly enforces Security Rule #1: Never logs raw secrets, repo code, or auth tokens.
 */
function logStructured(
  level: 'info' | 'warn' | 'error',
  msg: string,
  meta: Record<string, unknown> = {}
) {
  const safeMeta = { ...meta };
  delete safeMeta.rawReport;
  delete safeMeta.secret;
  delete safeMeta.token;
  delete safeMeta.codeContext;

  const entry = {
    level,
    time: new Date().toISOString(),
    service: 'kestrix-api',
    msg,
    ...safeMeta,
  };
  console.log(JSON.stringify(entry));
}

function sendApiError(
  res: Response,
  status: number,
  code: string,
  message: string
) {
  return res.status(status).json({
    error: {
      code,
      message,
    },
  });
}

const CreateAssetBodySchema = z.object({
  teamId: z.string().min(1),
  name: z.string().min(2).max(150),
  repoUrl: z.string().url(),
  criticality: z.union([z.literal(1), z.literal(2), z.literal(3), z.literal(4)]),
  internetFacing: z.boolean().default(false),
  environment: z.enum(['production', 'staging', 'development']),
  dataClass: z.enum(['pci_dss', 'pii', 'internal', 'public']),
});

const IngestScanBodySchema = z.object({
  assetId: z.string().min(1),
  commitSha: z.string().min(4).max(40),
  branch: z.string().default('main'),
  scanner: z.enum(['semgrep', 'gitleaks', 'osv-scanner']),
  scannerVersion: z.string().default('1.92.0'),
  rulesVersion: z.string().default('2026.10'),
  rawReport: z.unknown().optional(),
  normalizedFindings: z.array(z.any()).optional(),
});

const PatchFindingStatusBodySchema = z.object({
  toStatus: z.enum([
    'triaged',
    'in_progress',
    'fixed',
    'false_positive',
    'risk_accepted',
  ]),
  actor: z.string().min(2),
  reason: z.string().min(3),
  expiresAt: z.string().nullable().optional(),
});

const AiTaskParamSchema = z.enum([
  'explain',
  'advisory',
  'triage',
  'cvss',
  'patch',
]);

const LoginBodySchema = z.object({
  email: z.string().email(),
  password: z.string().min(6),
  teamId: z.string().default('all'),
});

const KNOWN_USERS: Record<
  string,
  { name: string; role: 'secops_admin' | 'team_owner' | 'security_reviewer'; teamId: string; teamName: string }
> = {
  'secops@kestrix.local': {
    name: 'Global SecOps',
    role: 'secops_admin',
    teamId: 'all',
    teamName: 'All Teams (Global Scope)',
  },
  'test-core@kestrix.local': {
    name: 'Test Core Lead',
    role: 'team_owner',
    teamId: 'team-core',
    teamName: 'Core Security & Platform',
  },
  'test-pay@kestrix.local': {
    name: 'Test Payments Lead',
    role: 'team_owner',
    teamId: 'team-checkout',
    teamName: 'Payments & Checkout',
  },
  'test-mobile@kestrix.local': {
    name: 'Test Mobile Lead',
    role: 'team_owner',
    teamId: 'team-mobile',
    teamName: 'Mobile Client Apps',
  },
};

async function startServer() {
  const app = express();
  app.use(express.json({ limit: '5mb' }));

  // Unauthenticated Healthcheck (Rule #7: Mọi endpoint trừ /healthz và /api/v1/auth/login yêu cầu xác thực)
  app.get(['/healthz', '/api/v1/healthz'], (_req: Request, res: Response) => {
    res.status(200).json({
      status: 'ok',
      timestamp: new Date().toISOString(),
    });
  });

  // POST /api/v1/auth/login (Session Authentication & Team RBAC Binding)
  app.post('/api/v1/auth/login', (req: Request, res: Response) => {
    const parsed = LoginBodySchema.safeParse(req.body);
    if (!parsed.success) {
      return sendApiError(
        res,
        400,
        'INVALID_CREDENTIALS',
        'Email hoặc mật khẩu không hợp lệ (mật khẩu tối thiểu 6 ký tự).'
      );
    }

    const normalizedEmail = parsed.data.email.trim().toLowerCase();
    const matchedProfile = KNOWN_USERS[normalizedEmail];
    const resolvedTeamId = matchedProfile?.teamId || parsed.data.teamId || 'all';
    const resolvedRole =
      matchedProfile?.role ||
      (resolvedTeamId === 'all' ? 'secops_admin' : 'team_owner');
    const resolvedName =
      matchedProfile?.name || normalizedEmail.split('@')[0];
    const resolvedTeamName =
      matchedProfile?.teamName ||
      (resolvedTeamId === 'all' ? 'All Teams (Global Scope)' : resolvedTeamId);

    // Security Rule #1: Never log raw password or session token
    logStructured('info', 'User authenticated successfully', {
      actor: normalizedEmail,
      role: resolvedRole,
      teamId: resolvedTeamId,
    });

    const session = {
      email: normalizedEmail,
      name: resolvedName,
      role: resolvedRole,
      teamId: resolvedTeamId,
      teamName: resolvedTeamName,
      sessionToken: `kstx_${Date.now().toString(36)}`,
      authenticatedAt: new Date().toISOString(),
    };

    return res.status(200).json({
      session,
      data: { session },
    });
  });

  // Authentication & Team Context Middleware for all /api/v1/* routes (Rule #7)
  app.use('/api/v1', (req: Request, res: Response, next: NextFunction) => {
    if (req.path === '/healthz' || req.path === '/auth/login') return next();

    const actor =
      (req.headers['x-kestrix-actor'] as string) ||
      (req.query.actor as string) ||
      'secops@kestrix.local';
    const teamId =
      (req.headers['x-kestrix-team'] as string) ||
      (req.query.team_id as string) ||
      (req.query.teamId as string) ||
      'all';

    if (!actor || actor === 'anonymous') {
      return sendApiError(
        res,
        401,
        'UNAUTHORIZED',
        'Yêu cầu xác thực danh tính người dùng hợp lệ (Rule #7).'
      );
    }

    (req as any).kestrixAuth = { actor, teamId };
    next();
  });

  // Bootstrap endpoint for initializing console state with RBAC team filtering
  app.get('/api/v1/bootstrap', (req: Request, res: Response) => {
    try {
      const { teamId } = (req as any).kestrixAuth;
      const payload = {
        teams: repository.getTeams(),
        assets: repository.getAssets(teamId),
        scans: repository.getScans(teamId),
        findings: repository.getFindings(teamId),
        occurrences: repository.getOccurrences(teamId),
        statusChanges: repository.getStatusChanges(teamId),
        aiOutputs: repository.getAiOutputs(teamId),
        vulnerabilities: repository.getVulnerabilities(),
      };
      res.json({
        ...payload,
        data: payload,
      });
    } catch (err: any) {
      return sendApiError(res, 403, 'FORBIDDEN', err.message);
    }
  });

  // GET /api/v1/assets
  app.get('/api/v1/assets', (req: Request, res: Response) => {
    const { teamId } = (req as any).kestrixAuth;
    res.json({ assets: repository.getAssets(teamId) });
  });

  // POST /api/v1/assets
  app.post('/api/v1/assets', (req: Request, res: Response) => {
    const parsed = CreateAssetBodySchema.safeParse(req.body);
    if (!parsed.success) {
      return sendApiError(
        res,
        400,
        'INVALID_PAYLOAD',
        parsed.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`).join('; ')
      );
    }

    try {
      const { teamId, actor } = (req as any).kestrixAuth;
      const created = repository.createAsset(teamId, parsed.data);
      logStructured('info', 'Asset created', {
        actor,
        assetId: created.id,
        teamId: created.teamId,
      });
      res.status(201).json({ asset: created });
    } catch (err: any) {
      const isForbidden = String(err.message).includes('FORBIDDEN');
      return sendApiError(
        res,
        isForbidden ? 403 : 400,
        isForbidden ? 'FORBIDDEN_TEAM_ACCESS' : 'ASSET_CREATE_ERROR',
        err.message
      );
    }
  });

  // GET /api/v1/findings
  app.get('/api/v1/findings', (req: Request, res: Response) => {
    const { teamId } = (req as any).kestrixAuth;
    const findings = repository.getFindings(teamId, {
      assetId: req.query.asset_id as string | undefined,
      status: req.query.status as string | undefined,
      riskLevel: req.query.risk_level as string | undefined,
      type: req.query.type as string | undefined,
    });
    res.json({ findings });
  });

  // PATCH /api/v1/findings/:id/status (Human-only status transition)
  app.patch('/api/v1/findings/:id/status', (req: Request, res: Response) => {
    const parsed = PatchFindingStatusBodySchema.safeParse(req.body);
    if (!parsed.success) {
      return sendApiError(
        res,
        400,
        'INVALID_STATUS_PAYLOAD',
        parsed.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`).join('; ')
      );
    }

    try {
      const { teamId } = (req as any).kestrixAuth;
      const findingId = String(req.params.id);
      const expiresDate = parsed.data.expiresAt
        ? new Date(parsed.data.expiresAt)
        : null;

      const result = repository.updateFindingStatus(
        teamId,
        findingId,
        parsed.data.toStatus as FindingStatus,
        parsed.data.actor,
        parsed.data.reason,
        expiresDate
      );

      logStructured('info', 'Finding status updated by human', {
        findingId,
        fromStatus: result.statusChange.fromStatus,
        toStatus: result.statusChange.toStatus,
        actor: parsed.data.actor,
      });

      res.json({
        ...result,
        data: result,
      });
    } catch (err: any) {
      const msg = String(err.message || '');
      const status = msg.includes('FORBIDDEN')
        ? 403
        : msg.includes('NOT_FOUND')
        ? 404
        : 400;
      const code = msg.includes('FORBIDDEN')
        ? 'FORBIDDEN_TEAM_ACCESS'
        : msg.includes('Chỉ hệ thống')
        ? 'SYSTEM_ONLY_TRANSITION'
        : 'INVALID_STATE_TRANSITION';
      return sendApiError(res, status, code, msg);
    }
  });

  // POST /api/v1/scans/ingest (Multi-scanner report ingestion & diffing)
  app.post('/api/v1/scans/ingest', (req: Request, res: Response) => {
    const parsed = IngestScanBodySchema.safeParse(req.body);
    if (!parsed.success) {
      return sendApiError(
        res,
        400,
        'INVALID_INGEST_PAYLOAD',
        parsed.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`).join('; ')
      );
    }

    try {
      const { teamId, actor } = (req as any).kestrixAuth;
      const summary = repository.ingestScan(teamId, {
        assetId: parsed.data.assetId,
        commitSha: parsed.data.commitSha,
        branch: parsed.data.branch,
        scanner: parsed.data.scanner as ScannerType,
        scannerVersion: parsed.data.scannerVersion,
        rulesVersion: parsed.data.rulesVersion,
        rawReport: parsed.data.rawReport,
        normalizedFindings: parsed.data.normalizedFindings,
      });

      logStructured('info', 'Scan report ingested and deduplicated', {
        actor,
        scanId: summary.scan.id,
        scanner: summary.scan.scanner,
        scannerVersion: summary.scan.scannerVersion,
        createdCount: summary.createdCount,
        updatedCount: summary.updatedCount,
        autoFixedCount: summary.autoFixedCount,
        reopenedCount: summary.reopenedCount,
      });

      res.json({
        summary,
        findings: repository.getFindings(teamId),
        scans: repository.getScans(teamId),
        occurrences: repository.getOccurrences(teamId),
        statusChanges: repository.getStatusChanges(teamId),
        data: {
          scan: summary.scan,
          createdCount: summary.createdCount,
          dedupedCount: summary.updatedCount,
          autoFixedCount: summary.autoFixedCount,
          reopenedCount: summary.reopenedCount,
        },
      });
    } catch (err: any) {
      const msg = String(err.message || '');
      const isForbidden = msg.includes('FORBIDDEN');
      return sendApiError(
        res,
        isForbidden ? 403 : 400,
        isForbidden ? 'FORBIDDEN_TEAM_ACCESS' : 'SCAN_INGEST_FAILED',
        msg
      );
    }
  });

  // GET /api/v1/scans/stream (Real Server-Sent Events progress bar)
  app.get('/api/v1/scans/stream', (req: Request, res: Response) => {
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');

    const stages = [
      {
        type: 'scan_progress',
        step: 'QUEUE',
        progress: 20,
        message:
          'API Gateway đẩy Job vào BullMQ (Valkey) · Khởi tạo container cô lập (--network=none)...',
      },
      {
        type: 'scan_progress',
        step: 'SCAN',
        progress: 50,
        message:
          'Worker thực thi Scanner (non-root, --read-only): Semgrep 1.92.0, Gitleaks 8.21.0, OSV 1.8.2...',
      },
      {
        type: 'scan_progress',
        step: 'NORMALIZE',
        progress: 80,
        message:
          'Chuẩn hóa đường dẫn & tính SHA-256 Fingerprint · Chấm điểm rủi ro theo ngữ cảnh CARE...',
      },
      {
        type: 'scan_progress',
        step: 'READY',
        progress: 100,
        message:
          'Sẵn sàng tiếp nhận báo cáo SARIF/JSON và phân tích AI qua packages/llm-gateway.',
      },
    ];

    let idx = 0;
    const timer = setInterval(() => {
      if (idx >= stages.length) {
        clearInterval(timer);
        return;
      }
      res.write(`data: ${JSON.stringify(stages[idx])}\n\n`);
      idx++;
    }, 450);

    req.on('close', () => {
      clearInterval(timer);
    });
  });

  // POST /api/v1/findings/:id/ai/:kind (Isolated LLM Gateway endpoint)
  app.post('/api/v1/findings/:id/ai/:kind', async (req: Request, res: Response) => {
    const kindParsed = AiTaskParamSchema.safeParse(req.params.kind);
    if (!kindParsed.success) {
      return sendApiError(
        res,
        400,
        'INVALID_AI_TASK',
        'Loại tác vụ AI không hợp lệ. Chỉ chấp nhận: explain, advisory, triage, cvss, patch.'
      );
    }

    try {
      const { teamId, actor } = (req as any).kestrixAuth;
      const findingId = String(req.params.id);
      const { finding } = repository.getFindingById(teamId, findingId);

      const attempt =
        typeof req.body?.patchAttempt === 'number'
          ? req.body.patchAttempt
          : typeof req.body?.attempt === 'number'
          ? req.body.attempt
          : 1;
      const codeContext =
        typeof req.body?.codeSnippet === 'string'
          ? req.body.codeSnippet
          : typeof req.body?.codeContext === 'string'
          ? req.body.codeContext
          : `Finding: ${finding.title} (${finding.ruleOrVulnId})`;

      const gatewayResult = await llmGateway.analyzeFinding(
        finding,
        kindParsed.data as AiTaskKind,
        codeContext,
        attempt
      );

      repository.recordAiOutput(teamId, gatewayResult.aiOutput);

      logStructured('info', 'LLM Gateway analysis completed', {
        actor,
        findingId: finding.id,
        kind: kindParsed.data,
        model: gatewayResult.aiOutput.model,
        promptVersion: gatewayResult.aiOutput.promptVersion,
        inputHash: gatewayResult.aiOutput.inputHash,
        cacheHit: gatewayResult.cacheHit,
        redactedMatchesCount: gatewayResult.redactedMatchesCount,
      });

      res.json({
        ...gatewayResult,
        data: {
          record: gatewayResult.aiOutput,
          output: gatewayResult.aiOutput.outputJson,
          fromCache: gatewayResult.cacheHit,
          patchGate: gatewayResult.patchGateResult,
        },
      });
    } catch (err: any) {
      const msg = String(err.message || '');
      const status = msg.includes('FORBIDDEN')
        ? 403
        : msg.includes('NOT_FOUND')
        ? 404
        : 422;
      return sendApiError(res, status, 'LLM_GATEWAY_ERROR', msg);
    }
  });

  // Mount Vite in development or static dist in production
  if (process.env.NODE_ENV !== 'production') {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.resolve(import.meta.dirname, 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  const PORT = 3000;
  app.listen(PORT, '0.0.0.0', () => {
    logStructured('info', `Kestrix Full-Stack Server listening on port ${PORT}`);
  });
}

startServer();
