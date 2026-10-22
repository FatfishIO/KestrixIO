import React, { useState } from 'react';
import { Finding, AiTaskKind, AiOutput } from '../core/types';
import { createSanitizedLlmPrompt } from '../core/llmGateway';
import { PatchVerificationGateResult } from '../core/pipeline';
import {
  Sparkles,
  ShieldCheck,
  Cpu,
  Lock,
  X,
  CheckCircle2,
  Code2,
  FileCheck,
  HelpCircle,
  BookOpen,
  RotateCcw,
  GitPullRequest,
} from 'lucide-react';

interface AiAdvisorDrawerProps {
  finding: Finding | null;
  onClose: () => void;
  onRecordAiOutput: (output: AiOutput) => void;
}

export const AiAdvisorDrawer: React.FC<AiAdvisorDrawerProps> = ({
  finding,
  onClose,
  onRecordAiOutput,
}) => {
  if (!finding) return null;

  const [activeTask, setActiveTask] = useState<AiTaskKind>('explain');
  const [isLoading, setIsLoading] = useState(false);
  const [resultData, setResultData] = useState<any>(null);
  const [validationSuccess, setValidationSuccess] = useState<boolean | null>(null);
  const [redactedCount, setRedactedCount] = useState(0);
  const [patchLoopAttempt, setPatchLoopAttempt] = useState<number>(1);
  const [patchGateResult, setPatchGateResult] = useState<PatchVerificationGateResult | null>(null);
  const [fromCache, setFromCache] = useState<boolean>(false);

  const sampleSnippet =
    finding.type === 'sast'
      ? `// File: src/routes/auth.ts:42\nconst user = await db.query(\`SELECT * FROM users WHERE email = '\${req.body.email}'\`);\nif (!user) return res.status(401).send("Invalid");`
      : finding.type === 'secret'
      ? `// File: deploy/production.env:14\nAWS_ACCESS_KEY_ID="TEST_AWS_KEY_SAMPLE_7EXAMPLE"\nDATABASE_URL="postgres://user:PLACEHOLDER_DB_PASS@db:5432/main"`
      : `// File: package.json:28\n"dependencies": {\n  "axios": "^0.21.1"\n}`;

  const runTask = async (kind: AiTaskKind, loopAttemptOverride?: number) => {
    setActiveTask(kind);
    setIsLoading(true);
    setResultData(null);
    setValidationSuccess(null);

    const currentAttempt = loopAttemptOverride ?? 1;
    setPatchLoopAttempt(currentAttempt);

    const prompt = createSanitizedLlmPrompt(
      `Execute task ${kind} on finding ${finding.ruleOrVulnId}`,
      sampleSnippet
    );

    const matches = prompt.match(/\[REDACTED_SECRET/g);
    setRedactedCount(matches ? matches.length : 0);

    try {
      const response = await fetch(`/api/v1/findings/${finding.id}/ai/${kind}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          codeSnippet: sampleSnippet,
          patchAttempt: currentAttempt,
        }),
      });

      if (response.ok) {
        const json = await response.json();
        const { record, output, fromCache: cached, patchGate } = json.data;
        setValidationSuccess(true);
        setResultData(output);
        setFromCache(Boolean(cached));
        if (patchGate) {
          setPatchGateResult(patchGate);
        }
        if (record) {
          onRecordAiOutput(record);
        }
      }
    } catch {
      // ignore network error
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="fixed inset-y-0 right-0 z-50 w-full max-w-xl bg-slate-900 border-l border-slate-800 shadow-2xl flex flex-col animate-slide-left">
      {/* Header */}
      <div className="p-4 border-b border-slate-800 flex items-center justify-between bg-slate-950/70">
        <div className="flex items-center space-x-2.5">
          <div className="w-8 h-8 rounded-lg bg-indigo-600/20 border border-indigo-500/40 flex items-center justify-center">
            <Sparkles className="w-4 h-4 text-indigo-400" />
          </div>
          <div>
            <h3 className="text-sm font-bold text-slate-100">AI Security Advisor</h3>
          </div>
        </div>
        <button
          onClick={onClose}
          className="p-1.5 text-slate-400 hover:text-slate-200 hover:bg-slate-800 rounded-lg transition-colors cursor-pointer"
        >
          <X className="w-5 h-5" />
        </button>
      </div>

      {/* Finding Subject Preview */}
      <div className="p-4 border-b border-slate-800 bg-slate-900/50">
        <div className="text-xs text-slate-400">Lỗ hổng đang phân tích:</div>
        <div className="text-sm font-semibold text-slate-200 mt-0.5">{finding.title}</div>
        <div className="text-xs font-mono text-indigo-400 mt-0.5">{finding.ruleOrVulnId}</div>
      </div>

      {/* 5 Task Selector Buttons */}
      <div className="p-4 border-b border-slate-800 grid grid-cols-2 sm:grid-cols-3 gap-2 bg-slate-950/40">
        <button
          onClick={() => runTask('explain')}
          className={`px-2.5 py-2 rounded-lg text-xs font-medium text-left transition-all cursor-pointer border ${
            activeTask === 'explain'
              ? 'bg-indigo-600/20 border-indigo-500/80 text-indigo-200'
              : 'bg-slate-900 border-slate-800 text-slate-300 hover:bg-slate-800'
          }`}
        >
          <div className="font-semibold flex items-center space-x-1">
            <HelpCircle className="w-3.5 h-3.5 shrink-0" />
            <span>1. Giải thích</span>
          </div>
          <div className="text-[10px] text-slate-400 mt-0.5">Ngữ cảnh & CWE/OWASP</div>
        </button>

        <button
          onClick={() => runTask('advisory')}
          className={`px-2.5 py-2 rounded-lg text-xs font-medium text-left transition-all cursor-pointer border ${
            activeTask === 'advisory'
              ? 'bg-indigo-600/20 border-indigo-500/80 text-indigo-200'
              : 'bg-slate-900 border-slate-800 text-slate-300 hover:bg-slate-800'
          }`}
        >
          <div className="font-semibold flex items-center space-x-1">
            <BookOpen className="w-3.5 h-3.5 shrink-0" />
            <span>2. Tóm tắt TTPs</span>
          </div>
          <div className="text-[10px] text-slate-400 mt-0.5">Advisory & Trích dẫn</div>
        </button>

        <button
          onClick={() => runTask('triage')}
          className={`px-2.5 py-2 rounded-lg text-xs font-medium text-left transition-all cursor-pointer border ${
            activeTask === 'triage'
              ? 'bg-indigo-600/20 border-indigo-500/80 text-indigo-200'
              : 'bg-slate-900 border-slate-800 text-slate-300 hover:bg-slate-800'
          }`}
        >
          <div className="font-semibold flex items-center space-x-1">
            <ShieldCheck className="w-3.5 h-3.5 shrink-0" />
            <span>3. Triage FP</span>
          </div>
          <div className="text-[10px] text-slate-400 mt-0.5">Gợi ý False Positive</div>
        </button>

        <button
          onClick={() => runTask('cvss')}
          className={`px-2.5 py-2 rounded-lg text-xs font-medium text-left transition-all cursor-pointer border ${
            activeTask === 'cvss'
              ? 'bg-indigo-600/20 border-indigo-500/80 text-indigo-200'
              : 'bg-slate-900 border-slate-800 text-slate-300 hover:bg-slate-800'
          }`}
        >
          <div className="font-semibold flex items-center space-x-1">
            <Cpu className="w-3.5 h-3.5 shrink-0" />
            <span>4. Dự đoán CVSS</span>
          </div>
          <div className="text-[10px] text-slate-400 mt-0.5">Nhãn [Dự đoán] bắt buộc</div>
        </button>

        <button
          onClick={() => runTask('patch', 1)}
          className={`px-2.5 py-2 rounded-lg text-xs font-medium text-left transition-all cursor-pointer border col-span-2 sm:col-span-1 ${
            activeTask === 'patch'
              ? 'bg-indigo-600/20 border-indigo-500/80 text-indigo-200'
              : 'bg-slate-900 border-slate-800 text-slate-300 hover:bg-slate-800'
          }`}
        >
          <div className="font-semibold flex items-center space-x-1">
            <Code2 className="w-3.5 h-3.5 shrink-0" />
            <span>5. Bản vá & Loop</span>
          </div>
          <div className="text-[10px] text-slate-400 mt-0.5">Self-Correction Sandbox</div>
        </button>
      </div>

      {/* Main Analysis Output Area */}
      <div className="flex-1 p-5 overflow-y-auto space-y-4">
        {isLoading ? (
          <div className="py-16 text-center space-y-3">
            <div className="w-8 h-8 border-2 border-indigo-500 border-t-transparent rounded-full animate-spin mx-auto"></div>
            <div className="text-xs text-slate-400">
              Đang gọi <code className="font-mono text-indigo-300">POST /api/v1/findings/{finding.id}/ai/{activeTask}</code> qua LLM Gateway...
            </div>
          </div>
        ) : resultData && validationSuccess ? (
          <div className="space-y-4 animate-fade-in">
            {/* Validation status bar */}
            <div className="flex items-center justify-between text-xs px-3 py-2 rounded-lg bg-slate-950 border border-slate-800">
              <div className="flex items-center space-x-2">
                <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                <span className="text-slate-300 font-mono">
                  Schema Zod: <strong className="text-emerald-400">PASSED</strong>
                  {fromCache ? ' · [CACHE HIT input_hash]' : ''}
                </span>
              </div>
              {redactedCount > 0 && (
                <span className="text-amber-400 text-[11px] font-mono">
                  {redactedCount} secret đã che
                </span>
              )}
            </div>

            {/* Task: Explain */}
            {activeTask === 'explain' && (
              <div className="space-y-3 text-xs">
                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                  <div className="font-semibold text-slate-200 mb-1">Tóm tắt Bản chất Lỗ hổng:</div>
                  <p className="text-slate-300 leading-relaxed">{resultData.summary}</p>
                </div>

                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                  <div className="font-semibold text-slate-200 mb-1">Tác động Kỹ thuật (Impact):</div>
                  <p className="text-slate-300 leading-relaxed">{resultData.technicalImpact}</p>
                </div>

                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                  <div className="font-semibold text-amber-300 mb-1">Kịch bản Khai thác (Scenario):</div>
                  <p className="text-slate-300 font-mono text-[11px] bg-slate-900 p-2 rounded border border-slate-800">
                    {resultData.exploitScenario}
                  </p>
                </div>

                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                  <div className="font-semibold text-cyan-300 mb-1">Ánh xạ CWE & OWASP:</div>
                  <div className="text-slate-300 font-mono">{resultData.cweMapping}</div>
                </div>

                <div className="p-3 rounded-lg bg-emerald-950/30 border border-emerald-900/50">
                  <div className="font-semibold text-emerald-300 mb-1">Khuyến nghị Khắc phục:</div>
                  <p className="text-emerald-200/90 leading-relaxed">{resultData.remediationAdvice}</p>
                </div>
              </div>
            )}

            {/* Task: Advisory & TTPs */}
            {activeTask === 'advisory' && (
              <div className="space-y-3 text-xs">
                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                  <div className="font-semibold text-slate-200 mb-1.5">
                    Phần mềm / Thành phần bị ảnh hưởng:
                  </div>
                  <ul className="space-y-1 font-mono text-indigo-300">
                    {resultData.affectedSoftware?.map((sw: string, i: number) => (
                      <li key={i}>• {sw}</li>
                    ))}
                  </ul>
                </div>

                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                  <div className="font-semibold text-amber-300 mb-1.5">
                    Phương thức & Kỹ thuật Khai thác (MITRE ATT&CK TTPs):
                  </div>
                  <ul className="space-y-1.5 text-slate-300">
                    {resultData.ttps?.map((ttp: string, i: number) => (
                      <li key={i} className="bg-slate-900 p-2 rounded border border-slate-800 font-mono text-[11px]">
                        {ttp}
                      </li>
                    ))}
                  </ul>
                </div>

                <div className="p-3 rounded-lg bg-emerald-950/30 border border-emerald-900/50">
                  <div className="font-semibold text-emerald-300 mb-1">Biện pháp Giảm thiểu (Mitigation):</div>
                  <p className="text-emerald-200/90 leading-relaxed">{resultData.mitigation}</p>
                </div>

                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                  <div className="font-semibold text-cyan-300 mb-1">
                    Nguồn Trích dẫn Bắt buộc (Chống Hallucination):
                  </div>
                  <ul className="space-y-1 font-mono text-[11px] text-slate-400">
                    {resultData.sourceCitations?.map((url: string, i: number) => (
                      <li key={i} className="truncate">
                        • {url}
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            )}

            {/* Task: Triage */}
            {activeTask === 'triage' && (
              <div className="space-y-3 text-xs">
                <div
                  className={`p-4 rounded-xl border ${
                    resultData.isLikelyFalsePositive
                      ? 'bg-amber-950/40 border-amber-800/80 text-amber-200'
                      : 'bg-rose-950/40 border-rose-800/80 text-rose-200'
                  }`}
                >
                  <div className="text-sm font-bold flex items-center justify-between">
                    <span>
                      {resultData.isLikelyFalsePositive
                        ? 'Gợi ý: CÓ THỂ LÀ FALSE POSITIVE'
                        : 'Gợi ý: TRUE POSITIVE (Lỗ hổng thực sự)'}
                    </span>
                    <span className="text-xs font-mono tabular-nums">
                      Tin cậy: {(resultData.confidence * 100).toFixed(0)}%
                    </span>
                  </div>
                  <p className="mt-2 text-xs leading-relaxed text-slate-300">
                    {resultData.reasoning}
                  </p>
                </div>

                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                  <div className="font-semibold text-slate-200 mb-1">Bằng chứng trong mã nguồn:</div>
                  <div className="font-mono text-slate-400 text-[11px] bg-slate-900 p-2 rounded">
                    {resultData.evidence}
                  </div>
                </div>
              </div>
            )}

            {/* Task: CVSS */}
            {activeTask === 'cvss' && (
              <div className="space-y-3 text-xs">
                <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-slate-400">Điểm số ước tính (Khi CNA chưa công bố):</span>
                    <div className="flex items-center space-x-2">
                      <span className="text-2xl font-bold font-mono tabular-nums text-rose-400">
                        {resultData.predictedScore}
                      </span>
                      <span className="px-2 py-0.5 rounded text-[10px] uppercase font-bold bg-amber-900/80 text-amber-200 border border-amber-700">
                        [Dự đoán]
                      </span>
                    </div>
                  </div>

                  <div className="pt-2 border-t border-slate-800 font-mono text-[11px] text-slate-300 break-all">
                    Vector: {resultData.predictedVector}
                  </div>

                  <div className="text-slate-400 text-[11px] tabular-nums">
                    Độ tin cậy: {(resultData.confidence * 100).toFixed(0)}% · Không bao giờ ghi đè điểm chính thức của CNA.
                  </div>
                </div>

                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                  <div className="font-semibold text-slate-200 mb-1">Cơ sở đánh giá kỹ thuật:</div>
                  <p className="text-slate-300 leading-relaxed">{resultData.rationale}</p>
                </div>
              </div>
            )}

            {/* Task: Patch + Self-Correction Loop */}
            {activeTask === 'patch' && (
              <div className="space-y-3 text-xs">
                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-semibold text-slate-200">
                      Mô tả bản vá (Vòng lặp #{patchLoopAttempt}):
                    </span>
                    <span className="font-mono text-[11px] text-indigo-300 tabular-nums">
                      Attempt {patchLoopAttempt}/3
                    </span>
                  </div>
                  <p className="text-slate-300">{resultData.description}</p>
                </div>

                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                  <div className="font-semibold text-slate-200 mb-2">Đề xuất Unified Diff:</div>
                  <pre className="p-3 rounded bg-slate-900 border border-slate-800 text-[11px] font-mono text-emerald-400 overflow-x-auto whitespace-pre">
                    {resultData.diffPatch}
                  </pre>
                </div>

                {/* Self-Correction Sandbox Gate Status */}
                {patchGateResult && (
                  <div
                    className={`p-3.5 rounded-xl border space-y-2 ${
                      patchGateResult.canOpenDraftPr
                        ? 'bg-emerald-950/30 border-emerald-800/70 text-emerald-200'
                        : 'bg-amber-950/40 border-amber-800/70 text-amber-200'
                    }`}
                  >
                    <div className="font-bold flex items-center justify-between">
                      <span>Cổng Kiểm Chứng Sandbox (Self-Correction Loop)</span>
                      <span className="font-mono text-[10px] uppercase px-2 py-0.5 rounded bg-slate-950">
                        {patchGateResult.status}
                      </span>
                    </div>
                    <p className="text-[11px] leading-relaxed">{patchGateResult.reason}</p>

                    {!patchGateResult.canOpenDraftPr ? (
                      <button
                        onClick={() => runTask('patch', 2)}
                        className="mt-2 w-full py-2 px-3 rounded-lg bg-amber-600 hover:bg-amber-500 text-slate-950 font-semibold text-xs flex items-center justify-center space-x-1.5 transition-colors cursor-pointer"
                      >
                        <RotateCcw className="w-3.5 h-3.5" />
                        <span>Chạy Vòng Lặp Tự Sửa Lỗi (Self-Correction Attempt #2)</span>
                      </button>
                    ) : (
                      <div className="pt-2 border-t border-emerald-800/50 flex items-center justify-between text-[11px]">
                        <span className="flex items-center space-x-1.5 text-emerald-300 font-semibold">
                          <GitPullRequest className="w-4 h-4" />
                          <span>Đủ điều kiện tạo Draft PR (GitHub App)</span>
                        </span>
                        <span className="font-mono text-[10px] text-rose-300">
                          Auto-Merge: BLOCKED (Rule #6)
                        </span>
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}
          </div>
        ) : (
          <div className="py-16 text-center space-y-2 text-slate-500">
            <Cpu className="w-8 h-8 mx-auto text-slate-600" />
            <p className="text-xs">Chọn một trong 5 điểm tích hợp AI ở trên để bắt đầu phân tích có kiểm soát.</p>
          </div>
        )}
      </div>

      {/* Footer */}
      <div className="p-4 border-t border-slate-800 bg-slate-950/80 flex items-center justify-between text-xs text-slate-400">
        <span>Ghi nhật ký vĩnh viễn vào bảng AiOutput</span>
        <button
          onClick={() => runTask(activeTask, patchLoopAttempt)}
          className="px-3 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white font-medium text-xs transition-colors cursor-pointer"
        >
          Chạy lại phân tích
        </button>
      </div>
    </div>
  );
};
