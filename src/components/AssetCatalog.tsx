import React, { useState } from 'react';
import { Asset, Team } from '../core/types';
import { Layers, Globe, Shield, Database, Plus, Check } from 'lucide-react';

interface AssetCatalogProps {
  assets: Asset[];
  teams: Team[];
  onAddAsset: (newAsset: Asset) => void;
}

export const AssetCatalog: React.FC<AssetCatalogProps> = ({ assets, teams, onAddAsset }) => {
  const [showAddForm, setShowAddForm] = useState(false);
  const [name, setName] = useState('');
  const [repoUrl, setRepoUrl] = useState('');
  const [teamId, setTeamId] = useState(teams[0]?.id || '');
  const [criticality, setCriticality] = useState<1 | 2 | 3 | 4>(2);
  const [internetFacing, setInternetFacing] = useState(false);
  const [environment, setEnvironment] = useState<'production' | 'staging' | 'development'>('production');
  const [dataClass, setDataClass] = useState<'pci_dss' | 'pii' | 'internal' | 'public'>('internal');

  const teamMap = new Map(teams.map((t) => [t.id, t]));

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!name || !repoUrl) return;

    const newAsset: Asset = {
      id: `asset-${Date.now()}`,
      teamId,
      name: name.trim(),
      repoUrl: repoUrl.trim(),
      criticality,
      internetFacing,
      environment,
      dataClass,
      createdAt: new Date().toISOString(),
    };

    onAddAsset(newAsset);
    setName('');
    setRepoUrl('');
    setShowAddForm(false);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-sm font-bold text-slate-100 flex items-center space-x-2">
            <Layers className="w-4 h-4 text-indigo-400" />
            <span>Assets & Teams</span>
          </h2>
        </div>

        <button
          onClick={() => setShowAddForm(!showAddForm)}
          className="px-3 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold flex items-center space-x-1.5 transition-colors cursor-pointer"
        >
          <Plus className="w-4 h-4" />
          <span>Thêm Asset Mới</span>
        </button>
      </div>

      {/* Add Form */}
      {showAddForm && (
        <form
          onSubmit={handleSubmit}
          className="p-5 bg-slate-900 border border-slate-800 rounded-xl space-y-4 animate-fade-in"
        >
          <div className="font-semibold text-sm text-slate-200">Khai báo Tài sản Mã nguồn Mới</div>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
            <div>
              <label className="block text-slate-400 mb-1">Tên Asset / Service</label>
              <input
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="e.g. order-settlement-service"
                className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-slate-200 focus:outline-none focus:border-indigo-500"
                required
              />
            </div>

            <div>
              <label className="block text-slate-400 mb-1">Repo URL Git</label>
              <input
                type="text"
                value={repoUrl}
                onChange={(e) => setRepoUrl(e.target.value)}
                placeholder="https://github.com/org/repo"
                className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-slate-200 focus:outline-none focus:border-indigo-500"
                required
              />
            </div>

            <div>
              <label className="block text-slate-400 mb-1">Team Sở hữu & Chịu SLA</label>
              <select
                value={teamId}
                onChange={(e) => setTeamId(e.target.value)}
                className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-slate-200 focus:outline-none focus:border-indigo-500"
              >
                {teams.map((t) => (
                  <option key={t.id} value={t.id}>
                    {t.name}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label className="block text-slate-400 mb-1">Độ quan trọng (Criticality: 1 Cao nhất - 4 Thấp nhất)</label>
              <select
                value={criticality}
                onChange={(e) => setCriticality(Number(e.target.value) as any)}
                className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-slate-200 focus:outline-none focus:border-indigo-500"
              >
                <option value={1}>Cấp 1 - Tối quan trọng (Core Payment, Auth)</option>
                <option value={2}>Cấp 2 - Quan trọng cao (Business Logic)</option>
                <option value={3}>Cấp 3 - Trung bình (Internal Portal)</option>
                <option value={4}>Cấp 4 - Phụ trợ / Tiện ích</option>
              </select>
            </div>

            <div>
              <label className="block text-slate-400 mb-1">Môi trường (Environment)</label>
              <select
                value={environment}
                onChange={(e) => setEnvironment(e.target.value as any)}
                className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-slate-200 focus:outline-none focus:border-indigo-500"
              >
                <option value="production">Production</option>
                <option value="staging">Staging</option>
                <option value="development">Development</option>
              </select>
            </div>

            <div>
              <label className="block text-slate-400 mb-1">Phân loại dữ liệu (Data Class)</label>
              <select
                value={dataClass}
                onChange={(e) => setDataClass(e.target.value as any)}
                className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-slate-200 focus:outline-none focus:border-indigo-500"
              >
                <option value="pci_dss">PCI-DSS (Dữ liệu thẻ / thanh toán)</option>
                <option value="pii">PII (Dữ liệu định danh cá nhân)</option>
                <option value="internal">Internal (Dữ liệu nội bộ)</option>
                <option value="public">Public (Công khai)</option>
              </select>
            </div>
          </div>

          <div className="flex items-center space-x-2 text-xs text-slate-300">
            <input
              type="checkbox"
              id="internetFacing"
              checked={internetFacing}
              onChange={(e) => setInternetFacing(e.target.checked)}
              className="rounded bg-slate-950 border-slate-800 text-indigo-600 focus:ring-0"
            />
            <label htmlFor="internetFacing">
              Tài sản tiếp xúc Internet công cộng (Internet-Facing)
            </label>
          </div>

          <div className="flex justify-end space-x-2">
            <button
              type="button"
              onClick={() => setShowAddForm(false)}
              className="px-3 py-1.5 bg-slate-800 text-slate-300 rounded-lg text-xs"
            >
              Hủy
            </button>
            <button
              type="submit"
              className="px-4 py-1.5 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg text-xs font-semibold"
            >
              Lưu Asset
            </button>
          </div>
        </form>
      )}

      {/* Asset Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {assets.map((asset) => {
          const team = teamMap.get(asset.teamId);
          return (
            <div
              key={asset.id}
              className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-4 hover:border-slate-700 transition-colors"
            >
              <div className="flex items-start justify-between">
                <div>
                  <h3 className="text-sm font-bold text-slate-100">{asset.name}</h3>
                  <div className="text-[11px] text-slate-400 font-mono mt-0.5 break-all">
                    {asset.repoUrl}
                  </div>
                </div>
                <span
                  className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase font-mono ${
                    asset.criticality === 1
                      ? 'bg-rose-950 text-rose-300 border border-rose-800'
                      : asset.criticality === 2
                      ? 'bg-amber-950 text-amber-300 border border-amber-800'
                      : 'bg-slate-800 text-slate-300'
                  }`}
                >
                  Cấp {asset.criticality}
                </span>
              </div>

              <div className="space-y-2 text-xs border-t border-slate-800/80 pt-3 text-slate-300">
                <div className="flex justify-between">
                  <span className="text-slate-500">Đội ngũ phụ trách:</span>
                  <span className="font-semibold text-indigo-300">{team?.name || 'Chưa gán'}</span>
                </div>

                <div className="flex justify-between">
                  <span className="text-slate-500">Môi trường:</span>
                  <span className="capitalize font-mono">{asset.environment}</span>
                </div>

                <div className="flex justify-between items-center">
                  <span className="text-slate-500">Internet-Facing:</span>
                  {asset.internetFacing ? (
                    <span className="px-1.5 py-0.2 rounded text-[10px] font-semibold bg-rose-950 text-rose-300 border border-rose-800 flex items-center space-x-1">
                      <Globe className="w-3 h-3 text-rose-400" />
                      <span>Công khai (Public)</span>
                    </span>
                  ) : (
                    <span className="px-1.5 py-0.2 rounded text-[10px] font-semibold bg-slate-800 text-slate-400">
                      Nội bộ (Private)
                    </span>
                  )}
                </div>

                <div className="flex justify-between">
                  <span className="text-slate-500">Dữ liệu xử lý:</span>
                  <span className="font-mono uppercase text-slate-400">{asset.dataClass}</span>
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
