import React, { useState } from 'react';
import { Finding, Asset, AiOutput } from '../core/types';
import {
  calculateAlertReductionFunnel,
  resolveVulnerabilityCvss,
} from '../core/pipeline';
import {
  Cpu,
  Database,
  Server,
  ShieldCheck,
  Filter,
  GitPullRequest,
  Play,
  CheckCircle2,
  Lock,
  Sparkles,
  Layers,
  AlertTriangle,
  ArrowRight,
  HardDrive,
  Activity,
} from 'lucide-react';

interface PipelineArchitectureProps {
  findings: Finding[];
  assets: Asset[];
  aiOutputs: AiOutput[];
  onOpenAiAdvisor: (finding: Finding) => void;
}

export const PipelineArchitecture: React.FC<PipelineArchitectureProps> = ({
  findings,
  assets,
  aiOutputs,
  onOpenAiAdvisor,
}) => {
  const [sseProgress, setSseProgress] = useState<number>(100);
  const [sseStage, setSseStage] = useState<string>(
    'Pipeline Idle · Sẵn sàng nhận Job qua BullMQ (Redis/Valkey)'
  );
  const [isSimulatingSse, setIsSimulatingSse] = useState(false);
  const [funnelMode, setFunnelMode] = useState<'live' | 'benchmark'>('benchmark');

  // Live funnel stats from current state (simulating multiple occurrences per finding)
  const liveRawDetections = findings.flatMap((f) => [
    { assetId: f.assetId, fingerprint: f.fingerprint, riskLevel: f.riskLevel },
    { assetId: f.assetId, fingerprint: f.fingerprint, riskLevel: f.riskLevel },
    { assetId: f.assetId, fingerprint: f.fingerprint, riskLevel: f.riskLevel },
  ]);
  const liveFunnel = calculateAlertReductionFunnel(liveRawDetections);

  // Benchmark stats from PLAN.md (3,983 raw detections -> 155 deduplicated -> 82 P1/P2)
  const displayFunnel =
    funnelMode === 'benchmark'
      ? {
          rawDetectionsCount: 3983,
          deduplicatedFindingsCount: 155,
          actionablePriorityCount: 82,
          llmEligibleCount: 82,
          totalReductionPercent: 97.9,
        }
      : liveFunnel;

  // Example CVSS resolution check
  const sampleOfficialCvss = resolveVulnerabilityCvss(
    {
      cvssScore: 9.8,
      cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
      cvssSource: 'CNA (GitHub Advisory)',
    },
    {
      predictedScore: 8.5,
      predictedVector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N',
      confidence: 0.89,
    }
  );

  const sampleFallbackCvss = resolveVulnerabilityCvss(
    { cvssScore: undefined, cvssVector: undefined },
    {
      predictedScore: 8.8,
      predictedVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
      confidence: 0.89,
    }
  );

  const triggerSsePipelineSimulation = () => {
    if (isSimulatingSse) return;
    setIsSimulatingSse(true);
    setSseProgress(10);
    setSseStage('[1/5] API Gateway (Fastify) đẩy Job vào BullMQ (Redis/Valkey)...');

    setTimeout(() => {
      setSseProgress(32);
      setSseStage(
        '[2/5] Worker chạy Container Scanner cô lập (--network=none, --read-only, non-root): Semgrep, Gitleaks, OSV-Scanner...'
      );
    }, 500);

    setTimeout(() => {
      setSseProgress(58);
      setSseStage(
        '[3/5] Lưu SARIF thô vào MinIO · Tính SHA-256 Fingerprint & Khử trùng lặp trên PostgreSQL...'
      );
    }, 1000);

    setTimeout(() => {
      setSseProgress(82);
      setSseStage(
        '[4/5] Chấm điểm rủi ro tất định (SSVC + CISA KEV + FIRST EPSS + Asset Context) -> Lọc P1/P2...'
      );
    }, 1500);

    setTimeout(() => {
      setSseProgress(100);
      setSseStage(
        '[5/5] Hoàn tất! Chỉ gửi các finding P1/P2 qua LLM Gateway (Redact Secret + Zod Schema) & cập nhật SSE.'
      );
      setIsSimulatingSse(false);
    }, 2000);
  };

  return (
    <div className="space-y-6">
      {/* 1. Closed-Loop Modular Monolith Architecture & Real-Time SSE Progress */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-5">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div>
            <h2 className="text-base font-bold text-slate-100 flex items-center space-x-2">
              <Server className="w-5 h-5 text-indigo-400" />
              <span>Kiến Trúc Pipeline Khép Kín: Phát Hiện → Làm Giàu → Ưu Tiên → Khắc Phục</span>
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Modular Monolith (Fastify API + BullMQ Worker) tách biệt hoàn toàn tác vụ nặng và cô lập mã nguồn không tin cậy.
            </p>
          </div>

          <button
            onClick={triggerSsePipelineSimulation}
            disabled={isSimulatingSse}
            className="px-3.5 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white text-xs font-semibold flex items-center space-x-2 transition-colors cursor-pointer"
          >
            <Play className="w-3.5 h-3.5" />
            <span>Mô phỏng Luồng Worker & SSE Progress</span>
          </button>
        </div>

        {/* Real-time SSE Progress Bar */}
        <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2">
          <div className="flex items-center justify-between text-xs">
            <span className="font-mono text-indigo-300 flex items-center space-x-2">
              <Activity className="w-3.5 h-3.5 text-emerald-400" />
              <span>SSE Stream (/api/v1/scans/stream): {sseStage}</span>
            </span>
            <span className="font-mono font-bold text-emerald-400">{sseProgress}%</span>
          </div>
          <div className="w-full h-2 bg-slate-900 rounded-full overflow-hidden border border-slate-800">
            <div
              className="h-full bg-gradient-to-r from-indigo-500 via-cyan-500 to-emerald-400 transition-all duration-300"
              style={{ width: `${sseProgress}%` }}
            />
          </div>
        </div>

        {/* 4 Architecture Pillars */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 text-xs">
          <div className="p-4 rounded-xl bg-slate-950/80 border border-slate-800 space-y-2">
            <div className="flex items-center justify-between text-indigo-400 font-semibold">
              <span>1. API Gateway & UI</span>
              <Layers className="w-4 h-4" />
            </div>
            <p className="text-slate-300 leading-relaxed">
              Fastify + Zod & Next.js Dashboard. Nhận SARIF/CycloneDX từ CI hoặc tạo job quét. Phát thanh tiến độ qua <strong>SSE</strong>.
            </p>
            <div className="text-[11px] font-mono text-slate-500 pt-1 border-t border-slate-800/80">
              RBAC theo Team ở tầng Service
            </div>
          </div>

          <div className="p-4 rounded-xl bg-slate-950/80 border border-slate-800 space-y-2">
            <div className="flex items-center justify-between text-cyan-400 font-semibold">
              <span>2. Async Worker & Scanners</span>
              <Cpu className="w-4 h-4" />
            </div>
            <p className="text-slate-300 leading-relaxed">
              BullMQ Worker chạy <strong>Semgrep</strong> (SAST), <strong>Gitleaks</strong> (Secret), <strong>OSV-Scanner</strong> (Dependency) trong container tạm.
            </p>
            <div className="text-[11px] font-mono text-emerald-400 pt-1 border-t border-slate-800/80">
              non-root · --read-only · --network=none
            </div>
          </div>

          <div className="p-4 rounded-xl bg-slate-950/80 border border-slate-800 space-y-2">
            <div className="flex items-center justify-between text-amber-400 font-semibold">
              <span>3. Data & Storage Layer</span>
              <Database className="w-4 h-4" />
            </div>
            <p className="text-slate-300 leading-relaxed">
              <strong>PostgreSQL + Drizzle</strong> lưu Finding, Occurrence, Scan diff. <strong>Redis/Valkey</strong> cho BullMQ. <strong>MinIO</strong> lưu raw SARIF.
            </p>
            <div className="text-[11px] font-mono text-slate-500 pt-1 border-t border-slate-800/80">
              Unique (asset_id, fingerprint)
            </div>
          </div>

          <div className="p-4 rounded-xl bg-slate-950/80 border border-slate-800 space-y-2">
            <div className="flex items-center justify-between text-violet-400 font-semibold">
              <span>4. Isolated LLM Gateway</span>
              <Lock className="w-4 h-4" />
            </div>
            <p className="text-slate-300 leading-relaxed">
              Cửa duy nhất gọi AI (hỗ trợ Cloud API & self-host Ollama/vLLM). Redact secret, kiểm soát token budget và lưu vết <code className="text-violet-300">AiOutput</code>.
            </p>
            <div className="text-[11px] font-mono text-violet-400 pt-1 border-t border-slate-800/80">
              Strict Zod Schema Validation
            </div>
          </div>
        </div>
      </div>

      {/* 2. Alert Reduction Funnel & SSVC Contextual Prioritization */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-sm font-bold text-slate-100 flex items-center space-x-2">
                <Filter className="w-4 h-4 text-emerald-400" />
                <span>Phễu Giảm Tải Cảnh Báo (Alert Reduction Funnel)</span>
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Giảm 97.9% cảnh báo nhờ khử trùng lặp Fingerprint và quy tắc tất định SSVC/EPSS/KEV.
              </p>
            </div>

            <div className="flex rounded-lg bg-slate-950 p-1 border border-slate-800 text-xs">
              <button
                onClick={() => setFunnelMode('benchmark')}
                className={`px-2.5 py-1 rounded-md font-medium cursor-pointer transition-colors ${
                  funnelMode === 'benchmark'
                    ? 'bg-indigo-600 text-white'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                Benchmark (3.983)
              </button>
              <button
                onClick={() => setFunnelMode('live')}
                className={`px-2.5 py-1 rounded-md font-medium cursor-pointer transition-colors ${
                  funnelMode === 'live'
                    ? 'bg-indigo-600 text-white'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                Live State ({liveFunnel.rawDetectionsCount})
              </button>
            </div>
          </div>

          <div className="space-y-3 text-xs">
            <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between">
              <div>
                <div className="font-semibold text-slate-200">
                  Bước 1: Cảnh báo thô từ Scanners (Raw Detections)
                </div>
                <div className="text-[11px] text-slate-400">
                  Tổng hợp từ Semgrep SARIF, Gitleaks và OSV-Scanner qua nhiều commit
                </div>
              </div>
              <span className="text-lg font-bold font-mono text-slate-200">
                {displayFunnel.rawDetectionsCount.toLocaleString()}
              </span>
            </div>

            <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between">
              <div>
                <div className="font-semibold text-cyan-300">
                  Bước 2: Khử trùng lặp bằng SHA-256 Fingerprint (Deduplication)
                </div>
                <div className="text-[11px] text-slate-400">
                  Gom theo (asset_id, fingerprint) không phụ thuộc số dòng hay version bump
                </div>
              </div>
              <span className="text-lg font-bold font-mono text-cyan-400">
                {displayFunnel.deduplicatedFindingsCount.toLocaleString()}
              </span>
            </div>

            <div className="p-3.5 rounded-lg bg-emerald-950/25 border border-emerald-800/60 flex items-center justify-between">
              <div>
                <div className="font-semibold text-emerald-300">
                  Bước 3: Ưu tiên hóa theo ngữ cảnh (SSVC + KEV + EPSS + Asset Context)
                </div>
                <div className="text-[11px] text-emerald-200/70">
                  Danh sách P1/P2 thực sự cần xử lý ngay & đủ điều kiện gọi LLM Enrichment
                </div>
              </div>
              <div className="text-right">
                <div className="text-lg font-bold font-mono text-emerald-400">
                  {displayFunnel.actionablePriorityCount.toLocaleString()}
                </div>
                <div className="text-[10px] font-mono text-emerald-300">
                  -{displayFunnel.totalReductionPercent.toFixed(1)}% nhiễu
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Right: Contextual Scoring vs AI Prediction Governance */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-4">
          <div>
            <h3 className="text-sm font-bold text-slate-100 flex items-center space-x-2">
              <ShieldCheck className="w-4 h-4 text-indigo-400" />
              <span>Nguyên Tắc Chấm Điểm & Dự Đoán Thuộc Tính Thiếu</span>
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Kết hợp OSV.dev, CVE.org (CNA), CISA KEV, FIRST EPSS v4 và CISA SSVC với ngữ cảnh tài sản.
            </p>
          </div>

          <div className="space-y-3 text-xs">
            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1.5">
              <div className="flex items-center justify-between">
                <span className="font-semibold text-slate-200">
                  Trường hợp 1: Đã có điểm CVSS từ CNA / CVE.org
                </span>
                <span className="px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800 font-mono text-[10px]">
                  {sampleOfficialCvss.badgeLabel}
                </span>
              </div>
              <div className="font-mono text-slate-300">
                Điểm sử dụng: <strong>{sampleOfficialCvss.score}</strong> ({sampleOfficialCvss.vector})
              </div>
              <div className="text-[11px] text-slate-400">
                Quy tắc Kestrix: Điểm AI dự đoán không bao giờ được ghi đè điểm chính thức của CNA.
              </div>
            </div>

            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1.5">
              <div className="flex items-center justify-between">
                <span className="font-semibold text-slate-200">
                  Trường hợp 2: CVE mới chưa được NVD/CNA chấm CVSS
                </span>
                <span className="px-2 py-0.5 rounded bg-amber-950 text-amber-300 border border-amber-800 font-mono text-[10px]">
                  {sampleFallbackCvss.badgeLabel}
                </span>
              </div>
              <div className="font-mono text-slate-300">
                Điểm tạm tính: <strong>{sampleFallbackCvss.score}</strong> ({sampleFallbackCvss.vector})
              </div>
              <div className="text-[11px] text-slate-400">
                Quy tắc Kestrix: Dùng dự đoán vector cơ sở làm tín hiệu phụ kèm nhãn <code className="text-amber-300">[Dự đoán]</code> và độ tin cậy.
              </div>
            </div>

            <div className="p-3 rounded-lg bg-indigo-950/30 border border-indigo-800/60 text-indigo-200 flex items-center justify-between">
              <div>
                <div className="font-semibold">Thử nghiệm 5 Điểm Tích Hợp AI trên Finding thực tế</div>
                <div className="text-[11px] text-indigo-300/80">
                  Giải thích · Trích xuất TTPs · Gợi ý False Positive · Dự đoán CVSS · Bản vá Self-Correction
                </div>
              </div>
              {findings[0] && (
                <button
                  onClick={() => onOpenAiAdvisor(findings[0])}
                  className="px-3 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white font-semibold text-xs shrink-0 cursor-pointer"
                >
                  Mở AI Advisor
                </button>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* 3. Engineering Fact-Check & Design Alignment Table (From PLAN.md) */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-4">
        <div>
          <h3 className="text-sm font-bold text-slate-100 flex items-center space-x-2">
            <Sparkles className="w-4 h-4 text-amber-400" />
            <span>Đối Chiếu Kiến Trúc & Đính Chính Kỹ Thuật (Theo docs/PLAN.md)</span>
          </h3>
          <p className="text-xs text-slate-400 mt-0.5">
            Cách Kestrix hiện thực hóa các khái niệm AI Vulnerability Management một cách an toàn, minh bạch và kiểm chứng được.
          </p>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs text-slate-300 border-collapse">
            <thead className="bg-slate-950 text-slate-400 font-mono uppercase text-[11px] border-b border-slate-800">
              <tr>
                <th className="py-3 px-4">Khái niệm đề xuất</th>
                <th className="py-3 px-4">Thực tế kỹ thuật (Theo PLAN.md)</th>
                <th className="py-3 px-4">Thiết kế chuẩn trong Kestrix v1</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70">
              <tr>
                <td className="py-3 px-4 font-semibold text-slate-200">
                  Giảm 98% cảnh báo (3.983 → 82)
                </td>
                <td className="py-3 px-4 text-slate-400">
                  3.983 detection giảm còn 155 nhờ khử trùng lặp, rồi còn 82 nhờ lọc quy tắc deterministic.
                </td>
                <td className="py-3 px-4 text-emerald-300">
                  Khử trùng lặp SHA-256 Fingerprint + Cây quyết định SSVC trước khi gọi LLM.
                </td>
              </tr>
              <tr>
                <td className="py-3 px-4 font-semibold text-slate-200">
                  Chấm điểm rủi ro ngữ cảnh (CARE)
                </td>
                <td className="py-3 px-4 text-slate-400">
                  Tránh dùng công thức nhân trọng số "ma thuật" hoặc để LLM tự sinh điểm rủi ro.
                </td>
                <td className="py-3 px-4 text-emerald-300">
                  Dùng cây quyết định SSVC + CISA KEV + FIRST EPSS + Asset Criticality kèm <code className="font-mono">risk_reasons</code>.
                </td>
              </tr>
              <tr>
                <td className="py-3 px-4 font-semibold text-slate-200">
                  Dự đoán CVSS còn thiếu (89.3%)
                </td>
                <td className="py-3 px-4 text-slate-400">
                  Dự đoán 8 chỉ số base CVSS v3.1 chỉ dùng khi nguồn CNA chưa công bố điểm.
                </td>
                <td className="py-3 px-4 text-emerald-300">
                  Không bao giờ ghi đè điểm CNA; luôn gắn nhãn bắt buộc <code className="font-mono">[Dự đoán]</code> và độ tin cậy.
                </td>
              </tr>
              <tr>
                <td className="py-3 px-4 font-semibold text-slate-200">
                  AI Auto-fix & Self-Correction Loop
                </td>
                <td className="py-3 px-4 text-slate-400">
                  Bản vá do LLM sinh ra có thể gây lỗi biên dịch hoặc chưa triệt tiêu hết lỗ hổng.
                </td>
                <td className="py-3 px-4 text-emerald-300">
                  Áp patch trong Sandbox → Chạy lại Scanner (0 finding) + Chạy Test → Chỉ mở <strong>Draft PR</strong> (cấm auto-merge).
                </td>
              </tr>
              <tr>
                <td className="py-3 px-4 font-semibold text-slate-200">
                  AI Copilot trong IDE / Pre-commit
                </td>
                <td className="py-3 px-4 text-slate-400">
                  Thuộc nhóm sản phẩm Shift-Left IDE riêng biệt, nằm ngoài phạm vi v1.
                </td>
                <td className="py-3 px-4 text-cyan-300">
                  Đã ghi nhận vào <code className="font-mono">docs/TODO.md</code> đúng quy tắc kiểm soát phạm vi.
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
