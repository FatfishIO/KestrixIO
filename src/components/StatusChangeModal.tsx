import React, { useState } from 'react';
import { Finding, FindingStatus, StatusChange } from '../core/types';
import { transitionFindingStatus } from '../core/stateMachine';
import { AlertCircle, Lock, Shield, X } from 'lucide-react';

interface StatusChangeModalProps {
  finding: Finding | null;
  defaultActor?: string;
  teamId?: string;
  onClose: () => void;
  onSuccess: (updatedFinding: Finding, newStatusChange: StatusChange) => void;
}

export const StatusChangeModal: React.FC<StatusChangeModalProps> = ({
  finding,
  defaultActor = 'secops@kestrix.local',
  teamId = 'all',
  onClose,
  onSuccess,
}) => {
  if (!finding) return null;

  const [toStatus, setToStatus] = useState<FindingStatus>('triaged');
  const [actor, setActor] = useState(defaultActor);
  const [reason, setReason] = useState('');
  const [expiresDays, setExpiresDays] = useState(30);
  const [error, setError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setIsSubmitting(true);

    try {
      let expiresAt: Date | null = null;
      if (toStatus === 'risk_accepted') {
        expiresAt = new Date();
        expiresAt.setDate(expiresAt.getDate() + expiresDays);
      }

      // First validate via pure stateMachine logic
      const localResult = transitionFindingStatus(
        {
          id: finding.id,
          assetId: finding.assetId,
          type: finding.type,
          fingerprint: finding.fingerprint,
          status: finding.status,
          reopened: finding.reopened,
        },
        toStatus,
        actor,
        reason,
        expiresAt
      );

      // Persist to full-stack backend API
      try {
        const response = await fetch(`/api/v1/findings/${finding.id}/status`, {
          method: 'PATCH',
          headers: {
            'Content-Type': 'application/json',
            'x-kestrix-actor': actor,
            'x-kestrix-team': teamId,
          },
          body: JSON.stringify({
            toStatus,
            actor,
            reason,
            expiresAt: expiresAt ? expiresAt.toISOString() : null,
          }),
        });
        if (response.ok) {
          const json = await response.json();
          onSuccess(json.data.finding, json.data.statusChange);
          onClose();
          return;
        } else {
          const errBody = await response.json();
          if (errBody.error?.message) {
            throw new Error(errBody.error.message);
          }
        }
      } catch (networkErr: any) {
        if (networkErr?.message?.includes('Không được phép') || networkErr?.message?.includes('Reason')) {
          throw networkErr;
        }
      }

      // Fallback if offline
      const updatedFullFinding: Finding = {
        ...finding,
        status: localResult.updatedFinding.status,
        reopened: localResult.updatedFinding.reopened,
      };

      onSuccess(updatedFullFinding, localResult.statusChange);
      onClose();
    } catch (err: any) {
      setError(err?.message || 'Có lỗi xảy ra khi cập nhật trạng thái');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fade-in">
      <div className="w-full max-w-lg bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl overflow-hidden">
        {/* Modal Header */}
        <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between bg-slate-950/60">
          <div className="flex items-center space-x-2">
            <Shield className="w-5 h-5 text-indigo-400" />
            <h3 className="text-base font-semibold text-slate-100">
              Quyết định Chuyển Trạng thái (Human Triage)
            </h3>
          </div>
          <button
            onClick={onClose}
            className="p-1 text-slate-400 hover:text-slate-200 hover:bg-slate-800 rounded-lg transition-colors cursor-pointer"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Form */}
        <form onSubmit={handleSubmit} className="p-6 space-y-4">
          {error && (
            <div className="p-3 rounded-lg bg-rose-950/80 border border-rose-800 text-xs text-rose-200 flex items-start space-x-2">
              <AlertCircle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
              <span>{error}</span>
            </div>
          )}

          <div>
            <label className="block text-xs font-medium text-slate-400 mb-1">
              Lỗ hổng đang xem xét
            </label>
            <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 text-xs space-y-1">
              <div className="font-semibold text-slate-200">{finding.title}</div>
              <div className="text-slate-400 font-mono text-[11px]">{finding.ruleOrVulnId}</div>
              <div className="text-slate-500 font-mono text-[10px]">
                Trạng thái hiện tại: <span className="uppercase text-indigo-400">{finding.status}</span>
              </div>
            </div>
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-400 mb-1">
              Người thực hiện (Actor)
            </label>
            <input
              type="text"
              value={actor}
              onChange={(e) => setActor(e.target.value)}
              placeholder="e.g. secops@kestrix.local"
              className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-sm text-slate-200 focus:outline-none focus:border-indigo-500"
              required
            />
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-400 mb-1">
              Trạng thái đích (To Status)
            </label>
            <select
              value={toStatus}
              onChange={(e) => setToStatus(e.target.value as FindingStatus)}
              className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-sm text-slate-200 focus:outline-none focus:border-indigo-500"
            >
              <option value="triaged">triaged (Xác nhận là lỗ hổng thật, cần sửa)</option>
              <option value="in_progress">in_progress (Đang giao việc cho team sửa)</option>
              <option value="false_positive">false_positive (Báo động giả)</option>
              <option value="risk_accepted">risk_accepted (Chấp nhận rủi ro có thời hạn)</option>
            </select>
          </div>

          {toStatus === 'risk_accepted' && (
            <div className="p-3 bg-amber-950/30 border border-amber-900/50 rounded-lg space-y-2">
              <label className="block text-xs font-semibold text-amber-300">
                Thời hạn ngoại lệ rủi ro (expires_at)
              </label>
              <div className="flex items-center space-x-3 text-xs text-slate-300">
                <input
                  type="number"
                  min={1}
                  max={365}
                  value={expiresDays}
                  onChange={(e) => setExpiresDays(Number(e.target.value))}
                  className="w-20 px-2 py-1 bg-slate-950 border border-slate-800 rounded text-slate-200 font-mono text-center"
                />
                <span>ngày kể từ hôm nay</span>
              </div>
            </div>
          )}

          <div>
            <label className="block text-xs font-medium text-slate-400 mb-1">
              Lý do thay đổi (Bắt buộc để kiểm toán - Audit Trail)
            </label>
            <textarea
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              placeholder="Giải thích vì sao chấp thuận, gắn ticket Jira, hoặc phân tích kỹ thuật chứng minh false positive..."
              rows={3}
              className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-sm text-slate-200 focus:outline-none focus:border-indigo-500"
              required
            />
          </div>

          <div className="pt-2 flex justify-end space-x-3">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 text-sm font-medium rounded-lg transition-colors cursor-pointer"
            >
              Hủy
            </button>
            <button
              type="submit"
              disabled={isSubmitting}
              className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white text-sm font-medium rounded-lg shadow-sm shadow-indigo-600/30 transition-colors cursor-pointer"
            >
              {isSubmitting ? 'Đang lưu...' : 'Lưu & Ghi Nhật ký Kiểm toán'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
