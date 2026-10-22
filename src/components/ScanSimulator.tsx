import React, { useState, useEffect } from 'react';
import { Finding, Asset, Scan, StatusChange, Occurrence } from '../core/types';
import {
  computeSastFingerprint,
  computeSecretFingerprint,
  normalizePath,
} from '../core/fingerprint';
import { processScanDiffAutoFixed } from '../core/stateMachine';
import {
  Play,
  RotateCcw,
  CheckCircle2,
  Key,
  ShieldCheck,
  Terminal,
  Upload,
  FileJson,
  Activity,
} from 'lucide-react';

interface ScanSimulatorProps {
  assets: Asset[];
  findings: Finding[];
  scans: Scan[];
  occurrences: Occurrence[];
  onUpdateState: (
    newFindings: Finding[],
    newScans: Scan[],
    newStatusChanges: StatusChange[],
    newOccurrences: Occurrence[]
  ) => void;
  onRefreshBootstrap?: () => Promise<void>;
}

const SAMPLE_SEMGREP_SARIF = JSON.stringify(
  {
    version: '2.1.0',
    runs: [
      {
        tool: { driver: { name: 'Semgrep OSS', semanticVersion: '1.92.0' } },
        results: [
          {
            ruleId: 'javascript.express.security.audit.xss.direct-response-write',
            level: 'error',
            message: {
              text: 'Detected directly writing user input to HTTP response without HTML encoding (Reflected XSS).',
            },
            partialFingerprints: {
              'primaryLocationLineHash/v1': 'semgrep-sarif-xss-hash-9001',
            },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: { uri: 'src/controllers/invoice.ts' },
                  region: {
                    startLine: 88,
                    endLine: 90,
                    snippet: { text: 'res.send(`<div>Invoice for ${req.query.customerName}</div>`);' },
                  },
                },
              },
            ],
          },
        ],
      },
    ],
  },
  null,
  2
);

const SAMPLE_GITLEAKS_JSON = JSON.stringify(
  [
    {
      RuleID: 'stripe-access-token',
      Description: 'Detected a Stripe Live Secret API Key potentially compromising payment infrastructure.',
      File: 'src/config/payments.ts',
      StartLine: 19,
      EndLine: 19,
      Secret: 'TEST_STRIPE_KEY_SAMPLE_77889900ABCD',
      Match: 'STRIPE_KEY = "TEST_STRIPE_KEY_SAMPLE_77889900ABCD"',
    },
  ],
  null,
  2
);

const SAMPLE_OSV_JSON = JSON.stringify(
  {
    results: [
      {
        source: { path: 'pnpm-lock.yaml' },
        packages: [
          {
            package: { name: 'jsonwebtoken', version: '8.5.1', ecosystem: 'npm' },
            vulnerabilities: [
              {
                id: 'CVE-2022-23529',
                aliases: ['GHSA-27h2-hvpr-p74q'],
                summary: 'Improper verification of cryptographic signature in jsonwebtoken <= 8.5.1 leads to RCE.',
                database_specific: { severity: 'CRITICAL', cvss_score: 9.8 },
              },
            ],
          },
        ],
      },
    ],
  },
  null,
  2
);

export const ScanSimulator: React.FC<ScanSimulatorProps> = ({
  assets,
  findings,
  scans,
  occurrences,
  onUpdateState,
  onRefreshBootstrap,
}) => {
  const [selectedAssetId, setSelectedAssetId] = useState(assets[0]?.id || '');
  const [scannerType, setScannerType] = useState<'semgrep' | 'gitleaks' | 'osv-scanner'>('semgrep');
  const [rawPayloadText, setRawPayloadText] = useState<string>(SAMPLE_SEMGREP_SARIF);
  const [simLog, setSimLog] = useState<string[]>([]);
  const [isProcessing, setIsProcessing] = useState(false);
  const [sseProgress, setSseProgress] = useState<{
    step?: string;
    progress?: number;
    message?: string;
  } | null>(null);

  const selectedAsset = assets.find((a) => a.id === selectedAssetId) || assets[0];

  const log = (msg: string) => {
    setSimLog((prev) => [`[${new Date().toLocaleTimeString()}] ${msg}`, ...prev]);
  };

  useEffect(() => {
    const evtSource = new EventSource('/api/v1/scans/stream');
    evtSource.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        if (data.type === 'scan_progress') {
          setSseProgress({
            step: data.step,
            progress: data.progress,
            message: data.message,
          });
          log(`[SSE Stream] (${data.progress}%) ${data.message}`);
        }
      } catch {
        // ignore heartbeat parse error
      }
    };
    return () => {
      evtSource.close();
    };
  }, []);

  const handleLoadSamplePayload = (scanner: 'semgrep' | 'gitleaks' | 'osv-scanner') => {
    setScannerType(scanner);
    if (scanner === 'semgrep') setRawPayloadText(SAMPLE_SEMGREP_SARIF);
    if (scanner === 'gitleaks') setRawPayloadText(SAMPLE_GITLEAKS_JSON);
    if (scanner === 'osv-scanner') setRawPayloadText(SAMPLE_OSV_JSON);
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (ev) => {
      const content = String(ev.target?.result || '');
      setRawPayloadText(content);
      log(`Đã tải file báo cáo: ${file.name} (${file.size} bytes)`);
    };
    reader.readAsText(file);
  };

  const handleRealScanIngest = async () => {
    if (!selectedAsset) return;
    setIsProcessing(true);
    try {
      const parsedPayload = JSON.parse(rawPayloadText);
      log(
        `--- Gửi báo cáo ${scannerType.toUpperCase()} tới POST /api/v1/scans/ingest (Asset: ${selectedAsset.name}) ---`
      );

      const response = await fetch('/api/v1/scans/ingest', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          assetId: selectedAsset.id,
          scanner: scannerType,
          commitSha: '9f8e7d6c',
          branch: 'main',
          rawReport: parsedPayload,
          isFullScan: false,
        }),
      });

      const body = await response.json();
      if (!response.ok) {
        log(`Lỗi API (${body.error?.code}): ${body.error?.message}`);
      } else {
        log(
          `=> INGEST THÀNH CÔNG: Scan ID ${body.data.scan.id} · Tạo mới: ${body.data.createdCount} · Khử trùng lặp: ${body.data.dedupedCount} · Auto-Fixed: ${body.data.autoFixedCount}`
        );
        if (onRefreshBootstrap) {
          await onRefreshBootstrap();
        }
      }
    } catch (err: any) {
      log(`Lỗi JSON hoặc kết nối: ${err?.message || 'Invalid JSON'}`);
    } finally {
      setIsProcessing(false);
    }
  };

  // 1. DEDUPLICATION TEST
  const runDedupDemo = () => {
    if (!selectedAsset) return;
    setIsProcessing(true);
    log(`--- Bắt đầu Scan Semgrep mới trên Asset: ${selectedAsset.name} ---`);

    const ruleId = 'javascript.express.security.audit.sqli';
    const filePath = 'src/routes/auth.ts';
    const snippet =
      "const user = await db.query(`SELECT * FROM users WHERE email = '${req.body.email}'`);";

    const calculatedFp = computeSastFingerprint(ruleId, filePath, snippet);
    log(`Tính toán Fingerprint: ${calculatedFp.slice(0, 16)}...`);

    const existing = findings.find(
      (f) => f.assetId === selectedAsset.id && f.fingerprint === calculatedFp
    );

    if (existing) {
      log(`=> KHỬ TRÙNG LẶP THÀNH CÔNG: Đã tìm thấy Finding ID: ${existing.id}`);
      log(
        `=> Giữ nguyên trạng thái (${existing.status}), cập nhật last_seen = now(). Không tạo duplicate finding!`
      );

      const updated = findings.map((f) =>
        f.id === existing.id ? { ...f, lastSeen: new Date().toISOString() } : f
      );

      const newScan: Scan = {
        id: `scan-${Date.now()}`,
        assetId: selectedAsset.id,
        commitSha: 'a1b2c3d4',
        branch: 'main',
        scanner: 'semgrep',
        scannerVersion: '1.92.0',
        rulesVersion: '2026.10',
        status: 'completed',
        findingsCount: 1,
        startedAt: new Date().toISOString(),
        completedAt: new Date().toISOString(),
      };

      onUpdateState(updated, [newScan, ...scans], [], occurrences);
    } else {
      log(`=> Chưa có finding này trên asset đang chọn.`);
    }

    setIsProcessing(false);
  };

  // 2. AUTO-FIXED TEST
  const runAutoFixDemo = () => {
    if (!selectedAsset) return;
    setIsProcessing(true);
    log(`--- Bắt đầu Quét Đầy Đủ (Full Scan) không còn lỗi trên: ${selectedAsset.name} ---`);
    log(`Dev đã fix code và commit bản vá an toàn.`);

    const emptyFingerprints = new Set<string>();
    const scanId = `scan-clean-${Date.now()}`;
    const commitSha = 'fix-c0ffee99';

    const { updatedFindings, statusChanges } = processScanDiffAutoFixed(
      findings.map((f) => ({
        id: f.id,
        assetId: f.assetId,
        type: f.type,
        fingerprint: f.fingerprint,
        status: f.status,
        reopened: f.reopened,
      })),
      selectedAsset.id,
      'sast',
      emptyFingerprints,
      scanId,
      commitSha
    );

    const mergedFindings = findings.map((f) => {
      const up = updatedFindings.find((u) => u.id === f.id);
      return up ? { ...f, status: up.status, reopened: up.reopened } : f;
    });

    log(`=> HỆ THỐNG TỰ ĐỘNG CHUYỂN SANG FIXED: ${statusChanges.length} findings được giải quyết.`);
    statusChanges.forEach((sc) => {
      log(
        `   [AUTO-FIXED] Finding ${sc.findingId} -> fixed. Lý do: "${sc.reason}" (Actor: ${sc.actor})`
      );
    });

    const newScan: Scan = {
      id: scanId,
      assetId: selectedAsset.id,
      commitSha,
      branch: 'main',
      scanner: 'semgrep',
      scannerVersion: '1.92.0',
      rulesVersion: '2026.10',
      status: 'completed',
      findingsCount: 0,
      startedAt: new Date().toISOString(),
      completedAt: new Date().toISOString(),
    };

    onUpdateState(mergedFindings, [newScan, ...scans], statusChanges, occurrences);
    setIsProcessing(false);
  };

  // 3. REOPENED TEST
  const runReopenDemo = () => {
    if (!selectedAsset) return;
    setIsProcessing(true);
    log(`--- Tái xuất hiện Lỗ hổng (Regression Scan) trên: ${selectedAsset.name} ---`);

    const target = findings.find((f) => f.assetId === selectedAsset.id);
    if (!target) {
      log(`Không tìm thấy finding nào cho asset này.`);
      setIsProcessing(false);
      return;
    }

    const fixedTargetList = findings.map((f) =>
      f.id === target.id ? { ...f, status: 'fixed' as const } : f
    );

    const scanId = `scan-regress-${Date.now()}`;
    const commitSha = 'regress-bad88';
    const activeFp = new Set([target.fingerprint]);

    const { updatedFindings, statusChanges } = processScanDiffAutoFixed(
      fixedTargetList.map((f) => ({
        id: f.id,
        assetId: f.assetId,
        type: f.type,
        fingerprint: f.fingerprint,
        status: f.status,
        reopened: f.reopened,
      })),
      selectedAsset.id,
      target.type,
      activeFp,
      scanId,
      commitSha
    );

    const merged = fixedTargetList.map((f) => {
      const up = updatedFindings.find((u) => u.id === f.id);
      return up ? { ...f, status: up.status, reopened: up.reopened } : f;
    });

    log(`=> PHÁT HIỆN REOPENED: Finding ${target.id} tái xuất hiện sau khi đã fixed!`);
    log(`=> Chuyển trạng thái về 'triaged' và đánh dấu cờ reopened = true.`);

    const newScan: Scan = {
      id: scanId,
      assetId: selectedAsset.id,
      commitSha,
      branch: 'main',
      scanner:
        target.type === 'sast' ? 'semgrep' : target.type === 'secret' ? 'gitleaks' : 'osv-scanner',
      scannerVersion: '1.0.0',
      rulesVersion: '2026.10',
      status: 'completed',
      findingsCount: 1,
      startedAt: new Date().toISOString(),
      completedAt: new Date().toISOString(),
    };

    onUpdateState(merged, [newScan, ...scans], statusChanges, occurrences);
    setIsProcessing(false);
  };

  // 4. PATH TRAVERSAL DEFENSE TEST
  const runPathTraversalDemo = () => {
    log(`--- Kiểm tra Chống Path Traversal (Quy tắc #9) ---`);
    const maliciousPaths = [
      '../../../../etc/passwd',
      'src/../../controllers/auth.ts',
      '..\\..\\windows\\system32\\cmd.exe',
      '/var/log/../../app/src/index.ts',
    ];

    maliciousPaths.forEach((path) => {
      const sanitized = normalizePath(path);
      log(`Đường dẫn đầu vào: "${path}" => Đã chuẩn hóa an toàn: "${sanitized}"`);
    });
    log(`=> Ngăn chặn hoàn toàn việc thoát khỏi root repo.`);
  };

  // 5. SECRET PROTECTION DEMO
  const runSecretProtectionDemo = () => {
    log(`--- Kiểm tra Bảo vệ Secret Tuyệt đối (Quy tắc #1) ---`);
    const rawSecret = 'ghp_super_secret_personal_access_token_999999';
    log(`Nhận diện Secret thô từ scanner: ${rawSecret.slice(0, 4)}... (Đang xử lý)`);

    const result = computeSecretFingerprint('github-pat', 'config/github.env', rawSecret);
    log(`1. Giá trị che (Masked): ${result.secretMasked}`);
    log(`2. Hash SHA-256 lưu DB: ${result.secretHash}`);
    log(`3. Fingerprint duy nhất: ${result.fingerprint}`);
    log(`=> BẢO MẬT: Giá trị thô bị hủy ngay tại bộ nhớ đệm, không lưu trong DB hay log!`);
  };

  return (
    <div className="space-y-6">
      {/* Real Report Parser & SSE Pipeline Ingestion */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
          <div>
            <div className="flex items-center space-x-2 text-indigo-400 font-semibold">
              <FileJson className="w-5 h-5" />
              <h2 className="text-base text-slate-100">
                Nạp Báo Cáo Quét Thực Tế (SARIF 2.1.0 / Gitleaks / OSV-Scanner)
              </h2>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Chuẩn hóa trực tiếp báo cáo từ Semgrep (ưu tiên partialFingerprints), Gitleaks (băm SHA-256 & che 4 ký tự cuối ngay lập tức) và OSV-Scanner qua <code className="font-mono text-indigo-300">POST /api/v1/scans/ingest</code>.
            </p>
          </div>

          <label className="inline-flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-slate-950 hover:bg-slate-800 border border-slate-800 text-xs text-slate-300 cursor-pointer transition-colors">
            <Upload className="w-3.5 h-3.5 text-indigo-400" />
            <span>Tải file JSON/SARIF</span>
            <input
              type="file"
              accept=".json,.sarif"
              onChange={handleFileUpload}
              className="hidden"
            />
          </label>
        </div>

        {/* Asset & Scanner Type Selector */}
        <div className="flex flex-wrap items-center gap-3 text-xs">
          <div className="flex items-center space-x-2">
            <span className="text-slate-400">Asset đích:</span>
            <select
              value={selectedAssetId}
              onChange={(e) => setSelectedAssetId(e.target.value)}
              className="px-3 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-slate-200 focus:outline-none focus:border-indigo-500"
            >
              {assets.map((asset) => (
                <option key={asset.id} value={asset.id}>
                  {asset.name} ({asset.environment} • Cấp {asset.criticality})
                </option>
              ))}
            </select>
          </div>

          <div className="flex items-center space-x-1.5">
            <span className="text-slate-400">Mẫu báo cáo chuẩn:</span>
            <button
              type="button"
              onClick={() => handleLoadSamplePayload('semgrep')}
              className={`px-2.5 py-1 rounded border font-mono cursor-pointer transition-colors ${
                scannerType === 'semgrep'
                  ? 'bg-indigo-600/20 border-indigo-500 text-indigo-200'
                  : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-slate-200'
              }`}
            >
              Semgrep SARIF 2.1.0
            </button>
            <button
              type="button"
              onClick={() => handleLoadSamplePayload('gitleaks')}
              className={`px-2.5 py-1 rounded border font-mono cursor-pointer transition-colors ${
                scannerType === 'gitleaks'
                  ? 'bg-indigo-600/20 border-indigo-500 text-indigo-200'
                  : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-slate-200'
              }`}
            >
              Gitleaks Secret JSON
            </button>
            <button
              type="button"
              onClick={() => handleLoadSamplePayload('osv-scanner')}
              className={`px-2.5 py-1 rounded border font-mono cursor-pointer transition-colors ${
                scannerType === 'osv-scanner'
                  ? 'bg-indigo-600/20 border-indigo-500 text-indigo-200'
                  : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-slate-200'
              }`}
            >
              OSV-Scanner JSON
            </button>
          </div>
        </div>

        {/* JSON Payload Editor */}
        <div>
          <textarea
            value={rawPayloadText}
            onChange={(e) => setRawPayloadText(e.target.value)}
            rows={8}
            className="w-full p-3 bg-slate-950 border border-slate-800 rounded-lg font-mono text-xs text-slate-200 focus:outline-none focus:border-indigo-500"
            spellCheck={false}
          />
        </div>

        {/* SSE Live Progress Bar & Submit */}
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 pt-1">
          {sseProgress ? (
            <div className="flex items-center space-x-3 text-xs text-emerald-400 font-mono">
              <Activity className="w-4 h-4 animate-pulse" />
              <span>
                SSE [{sseProgress.step}] {sseProgress.progress}% — {sseProgress.message}
              </span>
            </div>
          ) : (
            <div className="text-xs text-slate-500 font-mono">
              Kênh SSE <code className="text-slate-400">/api/v1/scans/stream</code> đang lắng nghe tiến độ...
            </div>
          )}

          <button
            type="button"
            onClick={handleRealScanIngest}
            disabled={isProcessing}
            className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white text-xs font-semibold rounded-lg transition-colors cursor-pointer self-start sm:self-auto"
          >
            Chạy Chuẩn Hóa & Chấm Điểm CARE
          </button>
        </div>
      </div>

      {/* Deterministic Scenario Presets */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6">
        <div className="flex items-center space-x-2 text-indigo-400 font-semibold mb-1">
          <Terminal className="w-5 h-5" />
          <h2 className="text-base text-slate-100">
            Kiểm Thử Nhanh 5 Quy Tắc Bảo Mật & Vòng Đời (Deterministic Scenarios)
          </h2>
        </div>
        <p className="text-xs text-slate-400">
          Mô phỏng nhanh các kịch bản: Khử trùng lặp fingerprint, tự động đánh dấu fixed, kích hoạt reopened khi tái xuất hiện, chống Path Traversal và bảo vệ Secret.
        </p>

        <div className="mt-4 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
          <button
            onClick={runDedupDemo}
            disabled={isProcessing}
            className="p-3 bg-slate-950 hover:bg-slate-800 border border-slate-800 rounded-xl text-left transition-all cursor-pointer group"
          >
            <div className="flex items-center space-x-2 text-cyan-400 font-semibold text-xs">
              <Play className="w-4 h-4" />
              <span>1. Test Dedup</span>
            </div>
            <div className="text-[11px] text-slate-400 mt-1">
              Quét lại finding cũ; kiểm tra không tạo duplicate.
            </div>
          </button>

          <button
            onClick={runAutoFixDemo}
            disabled={isProcessing}
            className="p-3 bg-slate-950 hover:bg-slate-800 border border-slate-800 rounded-xl text-left transition-all cursor-pointer group"
          >
            <div className="flex items-center space-x-2 text-emerald-400 font-semibold text-xs">
              <CheckCircle2 className="w-4 h-4" />
              <span>2. Test Auto-Fixed</span>
            </div>
            <div className="text-[11px] text-slate-400 mt-1">
              Lần quét sau vắng mặt finding; hệ thống tự đổi fixed.
            </div>
          </button>

          <button
            onClick={runReopenDemo}
            disabled={isProcessing}
            className="p-3 bg-slate-950 hover:bg-slate-800 border border-slate-800 rounded-xl text-left transition-all cursor-pointer group"
          >
            <div className="flex items-center space-x-2 text-indigo-400 font-semibold text-xs">
              <RotateCcw className="w-4 h-4" />
              <span>3. Test Reopened</span>
            </div>
            <div className="text-[11px] text-slate-400 mt-1">
              Finding fixed xuất hiện lại; chuyển triaged + reopened.
            </div>
          </button>

          <button
            onClick={runPathTraversalDemo}
            disabled={isProcessing}
            className="p-3 bg-slate-950 hover:bg-slate-800 border border-slate-800 rounded-xl text-left transition-all cursor-pointer group"
          >
            <div className="flex items-center space-x-2 text-amber-400 font-semibold text-xs">
              <ShieldCheck className="w-4 h-4" />
              <span>4. Path Traversal</span>
            </div>
            <div className="text-[11px] text-slate-400 mt-1">
              Xử lý chuỗi ../ và ..\ đảm bảo an toàn sandbox.
            </div>
          </button>

          <button
            onClick={runSecretProtectionDemo}
            disabled={isProcessing}
            className="p-3 bg-slate-950 hover:bg-slate-800 border border-slate-800 rounded-xl text-left transition-all cursor-pointer group"
          >
            <div className="flex items-center space-x-2 text-rose-400 font-semibold text-xs">
              <Key className="w-4 h-4" />
              <span>5. Rule #1 Secret</span>
            </div>
            <div className="text-[11px] text-slate-400 mt-1">
              Băm SHA-256 và che ****; không bao giờ lưu raw.
            </div>
          </button>
        </div>
      </div>

      {/* Simulator Execution Log */}
      <div className="bg-slate-950 border border-slate-800 rounded-xl p-4 font-mono text-xs">
        <div className="flex items-center justify-between pb-3 border-b border-slate-800 text-slate-400">
          <div className="flex items-center space-x-2">
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-500"></span>
            <span>Real-time Ingestion & Decision Engine Terminal</span>
          </div>
          {simLog.length > 0 && (
            <button
              onClick={() => setSimLog([])}
              className="text-[11px] text-slate-500 hover:text-slate-300 transition-colors cursor-pointer"
            >
              Xóa log
            </button>
          )}
        </div>

        <div className="mt-3 space-y-1.5 max-h-72 overflow-y-auto text-slate-300">
          {simLog.length === 0 ? (
            <div className="text-slate-600 py-6 text-center">
              Nạp báo cáo JSON/SARIF hoặc nhấn một trong các kịch bản ở trên để quan sát chu trình xử lý của Kestrix Engine.
            </div>
          ) : (
            simLog.map((line, idx) => (
              <div
                key={idx}
                className={`${
                  line.includes('AUTO-FIXED') || line.includes('THÀNH CÔNG')
                    ? 'text-emerald-400'
                    : line.includes('REOPENED')
                    ? 'text-amber-400 font-bold'
                    : line.includes('BẢO MẬT') || line.includes('SSE')
                    ? 'text-cyan-400'
                    : 'text-slate-300'
                }`}
              >
                {line}
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
};
