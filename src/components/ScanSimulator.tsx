import React, { useState, useEffect } from 'react';
import { Asset } from '../core/types';
import { Upload, FileJson, Activity } from 'lucide-react';

interface ScanSimulatorProps {
  assets: Asset[];
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
                    snippet: {
                      text: 'res.send(`<div>Invoice for ${req.query.customerName}</div>`);',
                    },
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
      Description:
        'Detected a Stripe Live Secret API Key potentially compromising payment infrastructure.',
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
                summary:
                  'Improper verification of cryptographic signature in jsonwebtoken <= 8.5.1 leads to RCE.',
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
          log(`[SSE] (${data.progress}%) ${data.message}`);
        }
      } catch {
        // ignore heartbeat
      }
    };
    return () => evtSource.close();
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
      setRawPayloadText(String(ev.target?.result || ''));
      log(`Đã nạp file: ${file.name} (${file.size} bytes)`);
    };
    reader.readAsText(file);
  };

  const handleRealScanIngest = async () => {
    if (!selectedAsset) return;
    setIsProcessing(true);
    try {
      const parsedPayload = JSON.parse(rawPayloadText);
      log(`POST /api/v1/scans/ingest · Scanner: ${scannerType} · Asset: ${selectedAsset.name}`);

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
        log(`Lỗi (${body.error?.code}): ${body.error?.message}`);
      } else {
        log(
          `THÀNH CÔNG: Scan ${body.data.scan.id} · Tạo mới: ${body.data.createdCount} · Dedup: ${body.data.dedupedCount} · Auto-Fixed: ${body.data.autoFixedCount}`
        );
        if (onRefreshBootstrap) {
          await onRefreshBootstrap();
        }
      }
    } catch (err: any) {
      log(`Lỗi JSON: ${err?.message || 'Invalid JSON'}`);
    } finally {
      setIsProcessing(false);
    }
  };

  return (
    <div className="space-y-5">
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center space-x-2 text-indigo-400 font-semibold">
            <FileJson className="w-5 h-5" />
            <h2 className="text-sm text-slate-100">Scan Report Ingest (SARIF / Gitleaks / OSV)</h2>
          </div>

          <label className="inline-flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-slate-950 hover:bg-slate-800 border border-slate-800 text-xs text-slate-300 cursor-pointer transition-colors">
            <Upload className="w-3.5 h-3.5 text-indigo-400" />
            <span>Upload JSON/SARIF</span>
            <input
              type="file"
              accept=".json,.sarif"
              onChange={handleFileUpload}
              className="hidden"
            />
          </label>
        </div>

        <div className="flex flex-wrap items-center gap-3 text-xs">
          <select
            value={selectedAssetId}
            onChange={(e) => setSelectedAssetId(e.target.value)}
            className="px-3 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-slate-200 focus:outline-none focus:border-indigo-500"
          >
            {assets.map((asset) => (
              <option key={asset.id} value={asset.id}>
                {asset.name} ({asset.environment} · Crit {asset.criticality})
              </option>
            ))}
          </select>

          <div className="flex items-center gap-1.5">
            {(['semgrep', 'gitleaks', 'osv-scanner'] as const).map((sc) => (
              <button
                key={sc}
                type="button"
                onClick={() => handleLoadSamplePayload(sc)}
                className={`px-2.5 py-1.5 rounded-lg border font-mono cursor-pointer transition-colors ${
                  scannerType === sc
                    ? 'bg-indigo-600/20 border-indigo-500 text-indigo-200'
                    : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-slate-200'
                }`}
              >
                {sc}
              </button>
            ))}
          </div>
        </div>

        <textarea
          value={rawPayloadText}
          onChange={(e) => setRawPayloadText(e.target.value)}
          rows={9}
          className="w-full p-3 bg-slate-950 border border-slate-800 rounded-lg font-mono text-xs text-slate-200 focus:outline-none focus:border-indigo-500"
          spellCheck={false}
        />

        <div className="flex flex-wrap items-center justify-between gap-3">
          {sseProgress ? (
            <div className="flex items-center space-x-2 text-xs text-emerald-400 font-mono">
              <Activity className="w-4 h-4 animate-pulse" />
              <span>
                [{sseProgress.step}] {sseProgress.progress}% — {sseProgress.message}
              </span>
            </div>
          ) : (
            <span className="text-xs text-slate-500 font-mono">SSE /api/v1/scans/stream ready</span>
          )}

          <button
            type="button"
            onClick={handleRealScanIngest}
            disabled={isProcessing}
            className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white text-xs font-semibold rounded-lg transition-colors cursor-pointer"
          >
            {isProcessing ? 'Đang xử lý...' : 'Ingest & Chấm Điểm CARE'}
          </button>
        </div>
      </div>

      {simLog.length > 0 && (
        <div className="bg-slate-950 border border-slate-800 rounded-xl p-4 font-mono text-xs">
          <div className="flex items-center justify-between pb-2 border-b border-slate-800 text-slate-400">
            <span>Ingest Output Log</span>
            <button
              onClick={() => setSimLog([])}
              className="text-[11px] text-slate-500 hover:text-slate-300 cursor-pointer"
            >
              Xóa
            </button>
          </div>
          <div className="mt-2 space-y-1 max-h-56 overflow-y-auto text-slate-300">
            {simLog.map((line, idx) => (
              <div
                key={idx}
                className={
                  line.includes('THÀNH CÔNG')
                    ? 'text-emerald-400'
                    : line.includes('Lỗi')
                    ? 'text-rose-400'
                    : 'text-slate-300'
                }
              >
                {line}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
