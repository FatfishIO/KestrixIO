import React, { useState } from 'react';
import { Finding, Asset, Team, Occurrence } from '../core/types';
import {
  Search,
  ChevronDown,
  ChevronRight,
} from 'lucide-react';

interface FindingsConsoleProps {
  findings: Finding[];
  assets: Asset[];
  teams: Team[];
  occurrences: Occurrence[];
  isLoading?: boolean;
  onOpenStatusModal: (finding: Finding) => void;
  onOpenAiAdvisor: (finding: Finding) => void;
  onNavigateToIngest?: () => void;
}

export const FindingsConsole: React.FC<FindingsConsoleProps> = ({
  findings,
  assets,
  occurrences,
  isLoading = false,
  onOpenStatusModal,
  onOpenAiAdvisor,
  onNavigateToIngest,
}) => {
  const [search, setSearch] = useState('');
  const [selectedRisk, setSelectedRisk] = useState<string>('all');
  const [selectedStatus, setSelectedStatus] = useState<string>('all');
  const [selectedType, setSelectedType] = useState<string>('all');
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const assetMap = new Map(assets.map((a) => [a.id, a]));

  const filteredFindings = findings.filter((f) => {
    if (selectedRisk !== 'all' && f.riskLevel !== selectedRisk) return false;
    if (selectedStatus !== 'all' && f.status !== selectedStatus) return false;
    if (selectedType !== 'all' && f.type !== selectedType) return false;
    if (search.trim()) {
      const q = search.toLowerCase();
      const matchTitle = f.title.toLowerCase().includes(q);
      const matchRule = f.ruleOrVulnId.toLowerCase().includes(q);
      const matchFp = f.fingerprint.toLowerCase().includes(q);
      return matchTitle || matchRule || matchFp;
    }
    return true;
  });

  const formatSlaText = (slaDue: string | null) => {
    if (!slaDue) return 'Không áp dụng SLA';
    const dueTime = new Date(slaDue).getTime();
    const now = Date.now();
    const diffHours = Math.round((dueTime - now) / (1000 * 60 * 60));
    const diffDays = Math.round(diffHours / 24);

    if (diffHours < 0) {
      return `Quá hạn SLA ${Math.abs(diffDays)} ngày`;
    }
    return `Hạn SLA còn ${diffDays} ngày`;
  };

  const getRiskTextClass = (level: string) => {
    switch (level) {
      case 'P1':
        return 'text-red-400 font-bold';
      case 'P2':
        return 'text-amber-400 font-semibold';
      case 'P3':
        return 'text-cyan-400 font-medium';
      default:
        return 'text-slate-400 font-medium';
    }
  };

  const getStatusTextClass = (status: string) => {
    switch (status) {
      case 'fixed':
        return 'text-emerald-400 font-semibold';
      case 'in_progress':
        return 'text-amber-300 font-medium';
      case 'triaged':
        return 'text-indigo-300 font-medium';
      case 'new':
        return 'text-sky-300 font-medium';
      default:
        return 'text-slate-400';
    }
  };

  const p1Count = findings.filter(
    (f) => f.riskLevel === 'P1' && f.status !== 'fixed'
  ).length;
  const p2Count = findings.filter(
    (f) => f.riskLevel === 'P2' && f.status !== 'fixed'
  ).length;
  const fixedCount = findings.filter((f) => f.status === 'fixed').length;
  const reopenedCount = findings.filter((f) => f.reopened).length;

  return (
    <div className="space-y-6">
      {/* KPI Metric Strip */}
      <div className="grid grid-cols-2 sm:grid-cols-4 border border-slate-800 rounded-xl bg-slate-900 divide-y sm:divide-y-0 sm:divide-x divide-slate-800">
        <div className="p-4">
          <div className="text-xs font-medium text-slate-400">P1 Critical (7d SLA)</div>
          <div className="mt-1.5 text-2xl font-bold text-red-400 font-mono tabular-nums">
            {p1Count}
          </div>
        </div>

        <div className="p-4">
          <div className="text-xs font-medium text-slate-400">P2 High (30d SLA)</div>
          <div className="mt-1.5 text-2xl font-bold text-amber-400 font-mono tabular-nums">
            {p2Count}
          </div>
        </div>

        <div className="p-4">
          <div className="text-xs font-medium text-slate-400">Fixed</div>
          <div className="mt-1.5 text-2xl font-bold text-emerald-400 font-mono tabular-nums">
            {fixedCount}
          </div>
        </div>

        <div className="p-4">
          <div className="text-xs font-medium text-slate-400">Reopened</div>
          <div className="mt-1.5 text-2xl font-bold text-indigo-400 font-mono tabular-nums">
            {reopenedCount}
          </div>
        </div>
      </div>

      {/* Filter & Search Toolbar */}
      <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 flex flex-wrap gap-3 items-center justify-between">
        <div className="relative flex-1 min-w-[240px]">
          <Search className="w-4 h-4 absolute left-3 top-2.5 text-slate-400" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Tìm theo tiêu đề, mã rule/CVE hoặc SHA-256 fingerprint..."
            className="w-full pl-9 pr-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-indigo-500"
          />
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <select
            value={selectedRisk}
            onChange={(e) => setSelectedRisk(e.target.value)}
            aria-label="Lọc theo mức độ rủi ro"
            className="px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs font-medium text-slate-300 focus:outline-none focus:border-indigo-500"
          >
            <option value="all">Tất cả mức rủi ro (P1–P4)</option>
            <option value="P1">P1 · Critical (7d)</option>
            <option value="P2">P2 · High (30d)</option>
            <option value="P3">P3 · Medium (90d)</option>
            <option value="P4">P4 · Low</option>
          </select>

          <select
            value={selectedStatus}
            onChange={(e) => setSelectedStatus(e.target.value)}
            aria-label="Lọc theo trạng thái vòng đời"
            className="px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs font-medium text-slate-300 focus:outline-none focus:border-indigo-500"
          >
            <option value="all">Tất cả trạng thái</option>
            <option value="new">new</option>
            <option value="triaged">triaged</option>
            <option value="in_progress">in_progress</option>
            <option value="fixed">fixed</option>
            <option value="false_positive">false_positive</option>
            <option value="risk_accepted">risk_accepted</option>
          </select>

          <select
            value={selectedType}
            onChange={(e) => setSelectedType(e.target.value)}
            aria-label="Lọc theo công cụ quét"
            className="px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs font-medium text-slate-300 focus:outline-none focus:border-indigo-500"
          >
            <option value="all">Tất cả loại lỗ hổng</option>
            <option value="sast">SAST · Semgrep</option>
            <option value="secret">Secret · Gitleaks</option>
            <option value="dependency">Dependency · OSV-Scanner</option>
          </select>
        </div>
      </div>

      {/* High-Density Findings Data Grid */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm text-slate-300">
            <thead className="bg-slate-950 border-b border-slate-800 text-xs font-mono text-slate-400">
              <tr>
                <th className="py-3 px-4 w-10"></th>
                <th className="py-3 px-4">Ưu tiên & SLA</th>
                <th className="py-3 px-4">Finding & Định danh</th>
                <th className="py-3 px-4">Tài sản & Ngữ cảnh</th>
                <th className="py-3 px-4">Trạng thái vòng đời</th>
                <th className="py-3 px-4 text-right">Thao tác</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {isLoading ? (
                Array.from({ length: 4 }).map((_, i) => (
                  <tr key={i} className="animate-pulse">
                    <td colSpan={6} className="py-4 px-4">
                      <div className="h-5 bg-slate-800 rounded w-full"></div>
                    </td>
                  </tr>
                ))
              ) : filteredFindings.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-12 px-4 text-center space-y-3">
                    <div className="text-sm text-slate-400">
                      Không có finding nào khớp với bộ lọc hoặc quyền truy cập team hiện tại.
                    </div>
                    {onNavigateToIngest && (
                      <button
                        onClick={onNavigateToIngest}
                        className="px-4 py-2 text-xs font-semibold text-white bg-indigo-600 rounded-lg hover:bg-indigo-500 transition-colors cursor-pointer"
                      >
                        Ingest Scan Report
                      </button>
                    )}
                  </td>
                </tr>
              ) : (
                filteredFindings.map((finding) => {
                  const asset = assetMap.get(finding.assetId);
                  const isExpanded = expandedId === finding.id;
                  const occList = occurrences.filter(
                    (o) => o.findingId === finding.id
                  );

                  return (
                    <React.Fragment key={finding.id}>
                      <tr className="hover:bg-slate-800/40 transition-colors">
                        <td className="py-3.5 px-4 text-center">
                          <button
                            onClick={() =>
                              setExpandedId(isExpanded ? null : finding.id)
                            }
                            aria-label="Mở rộng chi tiết finding"
                            className="p-1 hover:bg-slate-800 rounded text-slate-400 hover:text-slate-200 transition-colors cursor-pointer"
                          >
                            {isExpanded ? (
                              <ChevronDown className="w-4 h-4 text-indigo-400" />
                            ) : (
                              <ChevronRight className="w-4 h-4" />
                            )}
                          </button>
                        </td>

                        <td className="py-3.5 px-4 whitespace-nowrap font-mono tabular-nums">
                          <div className={`text-xs ${getRiskTextClass(finding.riskLevel)}`}>
                            {finding.riskLevel}
                          </div>
                          <div className="text-xs text-slate-400 mt-0.5">
                            {formatSlaText(finding.slaDue)}
                          </div>
                        </td>

                        <td className="py-3.5 px-4 max-w-md">
                          <div className="font-medium text-slate-100">
                            {finding.title}
                          </div>
                          <div className="flex items-center gap-2 text-xs text-slate-400 font-mono mt-0.5">
                            <span>{finding.type}</span>
                            <span aria-hidden="true">·</span>
                            <span>{finding.ruleOrVulnId}</span>
                            {finding.type === 'secret' && finding.secretMasked && (
                              <>
                                <span aria-hidden="true">·</span>
                                <span className="text-amber-300">
                                  Masked: {finding.secretMasked}
                                </span>
                              </>
                            )}
                          </div>
                        </td>

                        <td className="py-3.5 px-4 whitespace-nowrap">
                          <div className="text-xs font-medium text-slate-200">
                            {asset?.name || finding.assetId}
                          </div>
                          <div className="flex items-center gap-1.5 text-xs text-slate-400 mt-0.5 tabular-nums">
                            <span>{asset?.environment}</span>
                            <span aria-hidden="true">·</span>
                            <span>Crit {asset?.criticality}</span>
                            <span aria-hidden="true">·</span>
                            <span>
                              {asset?.internetFacing ? 'Internet-facing' : 'Internal'}
                            </span>
                          </div>
                        </td>

                        <td className="py-3.5 px-4 whitespace-nowrap font-mono tabular-nums">
                          <div className="flex items-center gap-2 text-xs">
                            <span className={getStatusTextClass(finding.status)}>
                              {finding.status}
                            </span>
                            {finding.reopened && (
                              <>
                                <span aria-hidden="true" className="text-slate-600">
                                  ·
                                </span>
                                <span className="text-red-400 font-semibold">
                                  reopened
                                </span>
                              </>
                            )}
                          </div>
                          <div className="text-xs text-slate-500 mt-0.5">
                            Cập nhật:{' '}
                            {new Date(finding.lastSeen).toLocaleTimeString([], {
                              hour: '2-digit',
                              minute: '2-digit',
                            })}
                          </div>
                        </td>

                        <td className="py-3.5 px-4 text-right whitespace-nowrap">
                          <div className="flex items-center justify-end gap-2">
                            <button
                              onClick={() => onOpenAiAdvisor(finding)}
                              className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-xs font-medium text-indigo-300 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                            >
                              AI Advisor
                            </button>

                            <button
                              onClick={() => onOpenStatusModal(finding)}
                              className="px-3 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-xs font-medium text-white transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                            >
                              Đổi trạng thái
                            </button>
                          </div>
                        </td>
                      </tr>

                      {isExpanded && (
                        <tr className="bg-slate-950">
                          <td colSpan={6} className="p-6">
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-8 text-xs">
                              <div className="space-y-3">
                                <div className="font-semibold text-slate-200">
                                  Tín hiệu quyết định mức rủi ro (Deterministic SSVC risk_reasons)
                                </div>
                                <ul className="space-y-1.5 text-slate-300 list-disc list-inside">
                                  {finding.riskReasons.map((reason, idx) => (
                                    <li key={idx}>{reason}</li>
                                  ))}
                                </ul>

                                <div className="pt-3 border-t border-slate-800 space-y-1">
                                  <div className="text-slate-400">
                                    SHA-256 Fingerprint (Unique per asset_id):
                                  </div>
                                  <div className="font-mono text-slate-300 break-all select-all">
                                    {finding.fingerprint}
                                  </div>
                                </div>
                              </div>

                              <div className="space-y-3">
                                <div className="font-semibold text-slate-200">
                                  Vị trí phát hiện (Occurrences) & Bảo mật Secret
                                </div>

                                {occList.length > 0 ? (
                                  <div className="space-y-1.5 font-mono">
                                    {occList.map((occ) => (
                                      <div
                                        key={occ.id}
                                        className="flex items-center justify-between py-1.5 border-b border-slate-800/80 text-slate-300 tabular-nums"
                                      >
                                        <span>
                                          {occ.filePath}
                                          {occ.lineStart ? `:${occ.lineStart}` : ''}
                                        </span>
                                        <span className="text-slate-500">
                                          Scan: {occ.scanId}
                                        </span>
                                      </div>
                                    ))}
                                  </div>
                                ) : (
                                  <div className="text-slate-500">
                                    Chưa có bản ghi vị trí chi tiết.
                                  </div>
                                )}

                                {finding.type === 'secret' && (
                                  <div className="pt-2 space-y-1 text-slate-300 font-mono">
                                    <div className="text-amber-300">
                                      Masked: {finding.secretMasked}
                                    </div>
                                    <div className="text-slate-400 break-all">
                                      SHA-256: {finding.secretHash}
                                    </div>
                                  </div>
                                )}
                              </div>
                            </div>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
