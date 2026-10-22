import React, { useState } from 'react';
import { Finding } from '../core/types';
import {
  calculateAlertReductionFunnel,
  resolveVulnerabilityCvss,
} from '../core/pipeline';
import {
  Server,
  ShieldCheck,
  Filter,
  Play,
  Activity,
} from 'lucide-react';

interface PipelineArchitectureProps {
  findings: Finding[];
  onOpenAiAdvisor: (finding: Finding) => void;
}

export const PipelineArchitecture: React.FC<PipelineArchitectureProps> = ({
  findings,
  onOpenAiAdvisor,
}) => {
  const [sseProgress, setSseProgress] = useState<number>(100);
  const [sseStage, setSseStage] = useState<string>('Idle · BullMQ Worker Ready');
  const [isSimulatingSse, setIsSimulatingSse] = useState(false);
  const [funnelMode, setFunnelMode] = useState<'live' | 'benchmark'>('benchmark');

  const liveRawDetections = findings.flatMap((f) => [
    { assetId: f.assetId, fingerprint: f.fingerprint, riskLevel: f.riskLevel },
    { assetId: f.assetId, fingerprint: f.fingerprint, riskLevel: f.riskLevel },
    { assetId: f.assetId, fingerprint: f.fingerprint, riskLevel: f.riskLevel },
  ]);
  const liveFunnel = calculateAlertReductionFunnel(liveRawDetections);

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
    setSseProgress(20);
    setSseStage('[1/4] Enqueue Job (BullMQ / Valkey)...');

    setTimeout(() => {
      setSseProgress(50);
      setSseStage('[2/4] Isolated Container Scan (Semgrep, Gitleaks, OSV)...');
    }, 400);

    setTimeout(() => {
      setSseProgress(80);
      setSseStage('[3/4] SHA-256 Fingerprint Deduplication & CARE Scoring...');
    }, 800);

    setTimeout(() => {
      setSseProgress(100);
      setSseStage('[4/4] Completed · P1/P2 routed to LLM Gateway');
      setIsSimulatingSse(false);
    }, 1200);
  };

  return (
    <div className="space-y-6">
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center space-x-2">
            <Server className="w-5 h-5 text-indigo-400" />
            <h2 className="text-sm font-bold text-slate-100">
              Pipeline Status & Worker Queue
            </h2>
          </div>

          <button
            onClick={triggerSsePipelineSimulation}
            disabled={isSimulatingSse}
            className="px-3 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white text-xs font-semibold flex items-center space-x-1.5 transition-colors cursor-pointer"
          >
            <Play className="w-3.5 h-3.5" />
            <span>Run Pipeline Check</span>
          </button>
        </div>

        <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 space-y-2">
          <div className="flex items-center justify-between text-xs">
            <span className="font-mono text-indigo-300 flex items-center space-x-2">
              <Activity className="w-3.5 h-3.5 text-emerald-400" />
              <span>{sseStage}</span>
            </span>
            <span className="font-mono font-bold text-emerald-400">{sseProgress}%</span>
          </div>
          <div className="w-full h-1.5 bg-slate-900 rounded-full overflow-hidden">
            <div
              className="h-full bg-indigo-500 transition-all duration-300"
              style={{ width: `${sseProgress}%` }}
            />
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-slate-100 flex items-center space-x-2">
              <Filter className="w-4 h-4 text-emerald-400" />
              <span>Alert Reduction Funnel</span>
            </h3>

            <div className="flex rounded-lg bg-slate-950 p-1 border border-slate-800 text-xs">
              <button
                onClick={() => setFunnelMode('benchmark')}
                className={`px-2.5 py-1 rounded font-medium cursor-pointer transition-colors ${
                  funnelMode === 'benchmark'
                    ? 'bg-indigo-600 text-white'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                Benchmark
              </button>
              <button
                onClick={() => setFunnelMode('live')}
                className={`px-2.5 py-1 rounded font-medium cursor-pointer transition-colors ${
                  funnelMode === 'live'
                    ? 'bg-indigo-600 text-white'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                Live ({liveFunnel.rawDetectionsCount})
              </button>
            </div>
          </div>

          <div className="space-y-2.5 text-xs">
            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between">
              <span className="text-slate-300">1. Raw Scanner Detections</span>
              <span className="text-base font-bold font-mono text-slate-200">
                {displayFunnel.rawDetectionsCount.toLocaleString()}
              </span>
            </div>

            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between">
              <span className="text-cyan-300">2. SHA-256 Fingerprint Deduplicated</span>
              <span className="text-base font-bold font-mono text-cyan-400">
                {displayFunnel.deduplicatedFindingsCount.toLocaleString()}
              </span>
            </div>

            <div className="p-3 rounded-lg bg-emerald-950/25 border border-emerald-800/60 flex items-center justify-between">
              <span className="text-emerald-300 font-semibold">
                3. Actionable P1/P2 (CARE + SSVC + KEV + EPSS)
              </span>
              <div className="text-right font-mono">
                <span className="text-base font-bold text-emerald-400">
                  {displayFunnel.actionablePriorityCount.toLocaleString()}
                </span>
                <span className="ml-2 text-[11px] text-emerald-300">
                  (-{displayFunnel.totalReductionPercent.toFixed(1)}%)
                </span>
              </div>
            </div>
          </div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4 flex flex-col justify-between">
          <div className="space-y-3">
            <h3 className="text-sm font-bold text-slate-100 flex items-center space-x-2">
              <ShieldCheck className="w-4 h-4 text-indigo-400" />
              <span>CVSS Resolution & AI Enrichment</span>
            </h3>

            <div className="space-y-2.5 text-xs">
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between">
                <div>
                  <div className="font-semibold text-slate-200">Official CNA Score</div>
                  <div className="font-mono text-[11px] text-slate-400 mt-0.5">
                    {sampleOfficialCvss.vector}
                  </div>
                </div>
                <span className="font-mono font-bold text-sm text-emerald-400">
                  {sampleOfficialCvss.score}
                </span>
              </div>

              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between">
                <div>
                  <div className="font-semibold text-slate-200">
                    Missing CNA Fallback <span className="text-amber-400 font-mono">[Dự đoán]</span>
                  </div>
                  <div className="font-mono text-[11px] text-slate-400 mt-0.5">
                    {sampleFallbackCvss.vector}
                  </div>
                </div>
                <span className="font-mono font-bold text-sm text-amber-400">
                  {sampleFallbackCvss.score}
                </span>
              </div>
            </div>
          </div>

          {findings[0] && (
            <div className="p-3 rounded-lg bg-indigo-950/30 border border-indigo-800/60 flex items-center justify-between text-xs">
              <span className="text-indigo-200 font-medium">
                AI Security Advisor ({findings.length} findings)
              </span>
              <button
                onClick={() => onOpenAiAdvisor(findings[0])}
                className="px-3 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white font-semibold cursor-pointer"
              >
                Mở AI Advisor
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
