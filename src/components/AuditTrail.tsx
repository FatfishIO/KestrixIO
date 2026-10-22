import React from 'react';
import { StatusChange, Finding } from '../core/types';
import { Lock, Shield, User, Bot, Clock, ArrowRight, History } from 'lucide-react';

interface AuditTrailProps {
  statusChanges: StatusChange[];
  findings: Finding[];
}

export const AuditTrail: React.FC<AuditTrailProps> = ({ statusChanges, findings }) => {
  const findingMap = new Map(findings.map((f) => [f.id, f]));

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-base font-bold text-slate-100 flex items-center space-x-2">
          <History className="w-5 h-5 text-indigo-400" />
          <span>Nhật Ký Kiểm Toán Bất Biến (Audit Trail & Status Governance)</span>
        </h2>
        <p className="text-xs text-slate-400 mt-0.5">
          Mọi quyết định phân loại, đóng lỗi, chấp nhận rủi ro hoặc tự động auto-fixed đều được lưu vết vĩnh viễn (STATE_MACHINE.md & ERD.md).
        </p>
      </div>

      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm text-slate-300">
            <thead className="bg-slate-950/80 border-b border-slate-800 text-xs uppercase font-mono text-slate-400">
              <tr>
                <th className="py-3.5 px-4">Thời gian</th>
                <th className="py-3.5 px-4">Tác nhân (Actor)</th>
                <th className="py-3.5 px-4">Lỗ hổng liên quan</th>
                <th className="py-3.5 px-4">Chuyển dịch trạng thái</th>
                <th className="py-3.5 px-4">Lý do ghi nhận (Reason)</th>
                <th className="py-3.5 px-4">Hết hạn (Expires)</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono text-xs">
              {statusChanges.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-12 text-center text-slate-500 font-sans">
                    Chưa có sự kiện chuyển đổi trạng thái nào được ghi nhận.
                  </td>
                </tr>
              ) : (
                statusChanges.map((change) => {
                  const finding = findingMap.get(change.findingId);
                  const isSystem = change.actor === 'system';

                  return (
                    <tr key={change.id} className="hover:bg-slate-800/30 transition-colors">
                      <td className="py-3.5 px-4 text-slate-400 whitespace-nowrap">
                        {new Date(change.changedAt).toLocaleString()}
                      </td>

                      <td className="py-3.5 px-4 whitespace-nowrap">
                        <span
                          className={`inline-flex items-center space-x-1.5 px-2 py-0.5 rounded text-xs ${
                            isSystem
                              ? 'bg-cyan-950/80 text-cyan-300 border border-cyan-800/60'
                              : 'bg-indigo-950/80 text-indigo-300 border border-indigo-800/60'
                          }`}
                        >
                          {isSystem ? (
                            <Bot className="w-3.5 h-3.5 text-cyan-400" />
                          ) : (
                            <User className="w-3.5 h-3.5 text-indigo-400" />
                          )}
                          <span>{change.actor}</span>
                        </span>
                      </td>

                      <td className="py-3.5 px-4 max-w-xs">
                        <div className="font-sans font-medium text-slate-200 truncate">
                          {finding?.title || change.findingId}
                        </div>
                        <div className="text-[11px] text-slate-500 font-mono">
                          {finding?.ruleOrVulnId}
                        </div>
                      </td>

                      <td className="py-3.5 px-4 whitespace-nowrap">
                        <div className="flex items-center space-x-1.5 font-bold uppercase text-[11px]">
                          <span className="text-slate-400">{change.fromStatus}</span>
                          <ArrowRight className="w-3.5 h-3.5 text-slate-500" />
                          <span
                            className={
                              change.toStatus === 'fixed'
                                ? 'text-emerald-400'
                                : change.toStatus === 'triaged'
                                ? 'text-purple-400'
                                : change.toStatus === 'in_progress'
                                ? 'text-amber-400'
                                : 'text-slate-300'
                            }
                          >
                            {change.toStatus}
                          </span>
                        </div>
                      </td>

                      <td className="py-3.5 px-4 font-sans text-slate-300 max-w-md">
                        {change.reason}
                      </td>

                      <td className="py-3.5 px-4 text-slate-400 whitespace-nowrap">
                        {change.expiresAt ? (
                          <span className="text-amber-400">
                            {new Date(change.expiresAt).toLocaleDateString()}
                          </span>
                        ) : (
                          <span className="text-slate-600">—</span>
                        )}
                      </td>
                    </tr>
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
