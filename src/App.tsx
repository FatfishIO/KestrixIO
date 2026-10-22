/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect, useCallback } from 'react';
import { Header } from './components/Header';
import { FindingsConsole } from './components/FindingsConsole';
import { StatusChangeModal } from './components/StatusChangeModal';
import { AiAdvisorDrawer } from './components/AiAdvisorDrawer';
import { ScanSimulator } from './components/ScanSimulator';
import { AssetCatalog } from './components/AssetCatalog';
import { AuditTrail } from './components/AuditTrail';
import { DocsViewer } from './components/DocsViewer';
import { PipelineArchitecture } from './components/PipelineArchitecture';
import { LoginPage, KestrixUserSession } from './components/LoginPage';
import {
  INITIAL_ASSETS,
  INITIAL_FINDINGS,
  INITIAL_OCCURRENCES,
  INITIAL_SCANS,
  INITIAL_STATUS_CHANGES,
  INITIAL_TEAMS,
  INITIAL_VULNERABILITIES,
} from './data/mockData';
import {
  Finding,
  StatusChange,
  AiOutput,
  Asset,
  Scan,
  Occurrence,
  Vulnerability,
} from './core/types';
import { Shield, FileText, Database, History, LogOut, UserCheck } from 'lucide-react';

const SESSION_STORAGE_KEY = 'kestrix_auth_session_v1';

export default function App() {
  const [userSession, setUserSession] = useState<KestrixUserSession | null>(() => {
    try {
      const saved = sessionStorage.getItem(SESSION_STORAGE_KEY);
      return saved ? (JSON.parse(saved) as KestrixUserSession) : null;
    } catch {
      return null;
    }
  });

  const [activeTab, setActiveTab] = useState<string>('findings');
  const [auditSubView, setAuditSubView] = useState<'audit' | 'vulns' | 'docs'>('audit');
  const [selectedTeamContext, setSelectedTeamContext] = useState<string>(
    userSession?.teamId || 'all'
  );

  const [findings, setFindings] = useState<Finding[]>(INITIAL_FINDINGS);
  const [assets, setAssets] = useState<Asset[]>(INITIAL_ASSETS);
  const [teams, setTeams] = useState(INITIAL_TEAMS);
  const [scans, setScans] = useState<Scan[]>(INITIAL_SCANS);
  const [occurrences, setOccurrences] = useState<Occurrence[]>(INITIAL_OCCURRENCES);
  const [vulnerabilities, setVulnerabilities] =
    useState<Vulnerability[]>(INITIAL_VULNERABILITIES);
  const [statusChanges, setStatusChanges] =
    useState<StatusChange[]>(INITIAL_STATUS_CHANGES);
  const [aiOutputs, setAiOutputs] = useState<AiOutput[]>([]);

  // Modals & Drawers
  const [statusModalFinding, setStatusModalFinding] = useState<Finding | null>(null);
  const [aiDrawerFinding, setAiDrawerFinding] = useState<Finding | null>(null);

  const handleLoginSuccess = (session: KestrixUserSession) => {
    setUserSession(session);
    setSelectedTeamContext(session.teamId);
    try {
      sessionStorage.setItem(SESSION_STORAGE_KEY, JSON.stringify(session));
    } catch {
      // ignore storage quota errors
    }
  };

  const handleLogout = () => {
    setUserSession(null);
    setStatusModalFinding(null);
    setAiDrawerFinding(null);
    try {
      sessionStorage.removeItem(SESSION_STORAGE_KEY);
    } catch {
      // ignore
    }
  };

  const refreshFromBackend = useCallback(async () => {
    if (!userSession) return;
    try {
      const query =
        selectedTeamContext !== 'all'
          ? `?teamId=${encodeURIComponent(selectedTeamContext)}`
          : '';
      const res = await fetch(`/api/v1/bootstrap${query}`, {
        headers: {
          'x-kestrix-actor': userSession.email,
          'x-kestrix-team': selectedTeamContext,
        },
      });
      if (!res.ok) return;
      const json = await res.json();
      if (json.data) {
        setTeams(json.data.teams || INITIAL_TEAMS);
        setAssets(json.data.assets || INITIAL_ASSETS);
        setFindings(json.data.findings || INITIAL_FINDINGS);
        setScans(json.data.scans || INITIAL_SCANS);
        setOccurrences(json.data.occurrences || INITIAL_OCCURRENCES);
        setVulnerabilities(json.data.vulnerabilities || INITIAL_VULNERABILITIES);
        setStatusChanges(json.data.statusChanges || INITIAL_STATUS_CHANGES);
        setAiOutputs(json.data.aiOutputs || []);
      }
    } catch {
      // Keep local deterministic state if offline
    }
  }, [selectedTeamContext, userSession]);

  useEffect(() => {
    refreshFromBackend();
  }, [refreshFromBackend]);

  // Render Login Page if not authenticated
  if (!userSession) {
    return <LoginPage onLoginSuccess={handleLoginSuccess} />;
  }

  // Filter client-side as well if team context is selected
  const visibleAssets =
    selectedTeamContext === 'all'
      ? assets
      : assets.filter((a) => a.teamId === selectedTeamContext);
  const visibleAssetIds = new Set(visibleAssets.map((a) => a.id));
  const visibleFindings = findings.filter((f) => visibleAssetIds.has(f.assetId));

  const handleStatusChangeSuccess = (
    updatedFinding: Finding,
    newStatusChange: StatusChange
  ) => {
    setFindings((prev) =>
      prev.map((f) => (f.id === updatedFinding.id ? updatedFinding : f))
    );
    setStatusChanges((prev) => [newStatusChange, ...prev]);
  };

  const handleRecordAiOutput = (output: AiOutput) => {
    setAiOutputs((prev) => [output, ...prev]);
  };

  const handleSimulatorUpdate = (
    newFindings: Finding[],
    newScans: Scan[],
    newStatusChanges: StatusChange[],
    newOccurrences: Occurrence[]
  ) => {
    setFindings(newFindings);
    setScans(newScans);
    setStatusChanges((prev) => [...newStatusChanges, ...prev]);
    setOccurrences(newOccurrences);
  };

  const handleAddAsset = async (newAsset: Asset) => {
    setAssets((prev) => [newAsset, ...prev]);
    try {
      await fetch('/api/v1/assets', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-kestrix-actor': userSession.email,
          'x-kestrix-team': selectedTeamContext,
        },
        body: JSON.stringify({
          teamId: newAsset.teamId,
          name: newAsset.name,
          repoUrl: newAsset.repoUrl,
          criticality: newAsset.criticality,
          internetFacing: newAsset.internetFacing,
          environment: newAsset.environment,
          dataClass: newAsset.dataClass,
        }),
      });
      await refreshFromBackend();
    } catch {
      // Keep optimistic update
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-indigo-500 selection:text-white">
      {/* 3-Zone Top Header */}
      <Header activeTab={activeTab} setActiveTab={setActiveTab} />

      {/* Workspace Context Bar (Authenticated Identity & Team RBAC Scope - Rule #7) */}
      <div className="bg-slate-900/50 border-b border-slate-800/80">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-2 flex flex-wrap items-center justify-between gap-3 text-xs">
          <div className="flex flex-wrap items-center gap-4 text-slate-400">
            <div className="flex items-center space-x-2">
              <UserCheck className="w-3.5 h-3.5 text-emerald-400" />
              <span className="text-slate-200 font-medium">{userSession.name}</span>
              <span className="font-mono text-[11px] text-indigo-400">
                ({userSession.email})
              </span>
            </div>

            <span className="text-slate-700">|</span>

            <div className="flex items-center space-x-2">
              <Shield className="w-3.5 h-3.5 text-indigo-400" />
              <span>Team RBAC Scope:</span>
              <select
                value={selectedTeamContext}
                onChange={(e) => setSelectedTeamContext(e.target.value)}
                disabled={userSession.role !== 'secops_admin'}
                className="px-2.5 py-1 bg-slate-950 border border-slate-800 rounded text-slate-200 font-medium focus:outline-none focus:border-indigo-500 disabled:opacity-75"
              >
                <option value="all">Global SecOps (Tất cả Team)</option>
                {teams.map((team) => (
                  <option key={team.id} value={team.id}>
                    Team: {team.name} ({team.id})
                  </option>
                ))}
              </select>
            </div>
          </div>

          <div className="flex items-center space-x-4 text-slate-400 font-mono text-[11px] tabular-nums">
            <span>Assets: {visibleAssets.length}</span>
            <span>·</span>
            <span>Findings: {visibleFindings.length}</span>
            <span>·</span>
            <button
              type="button"
              onClick={handleLogout}
              className="inline-flex items-center space-x-1 text-rose-400 hover:text-rose-300 font-sans font-medium cursor-pointer transition-colors"
            >
              <LogOut className="w-3.5 h-3.5" />
              <span>Đăng xuất</span>
            </button>
          </div>
        </div>
      </div>

      {/* Main Container */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {activeTab === 'findings' && (
          <FindingsConsole
            findings={visibleFindings}
            assets={visibleAssets}
            teams={teams}
            occurrences={occurrences}
            onOpenStatusModal={(f) => setStatusModalFinding(f)}
            onOpenAiAdvisor={(f) => setAiDrawerFinding(f)}
          />
        )}

        {activeTab === 'assets' && (
          <AssetCatalog
            assets={visibleAssets}
            teams={teams}
            onAddAsset={handleAddAsset}
          />
        )}

        {activeTab === 'scanners' && (
          <ScanSimulator
            assets={visibleAssets}
            findings={visibleFindings}
            scans={scans}
            occurrences={occurrences}
            onUpdateState={handleSimulatorUpdate}
            onRefreshBootstrap={refreshFromBackend}
          />
        )}

        {activeTab === 'advisor' && (
          <PipelineArchitecture
            findings={visibleFindings}
            assets={visibleAssets}
            aiOutputs={aiOutputs}
            onOpenAiAdvisor={(f) => setAiDrawerFinding(f)}
          />
        )}

        {activeTab === 'audit' && (
          <div className="space-y-5">
            {/* Sub-navigation for Audit, Vulnerability Cache, and Architecture Docs */}
            <div className="flex flex-wrap items-center gap-2 border-b border-slate-800 pb-3">
              <button
                onClick={() => setAuditSubView('audit')}
                className={`px-3 py-1.5 rounded-lg text-xs font-medium flex items-center space-x-1.5 cursor-pointer transition-colors ${
                  auditSubView === 'audit'
                    ? 'bg-slate-800 text-white'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                <History className="w-3.5 h-3.5 text-indigo-400" />
                <span>Nhật ký StatusChange ({statusChanges.length})</span>
              </button>

              <button
                onClick={() => setAuditSubView('vulns')}
                className={`px-3 py-1.5 rounded-lg text-xs font-medium flex items-center space-x-1.5 cursor-pointer transition-colors ${
                  auditSubView === 'vulns'
                    ? 'bg-slate-800 text-white'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                <Database className="w-3.5 h-3.5 text-cyan-400" />
                <span>Vulnerability Cache: OSV / CVE / KEV / EPSS ({vulnerabilities.length})</span>
              </button>

              <button
                onClick={() => setAuditSubView('docs')}
                className={`px-3 py-1.5 rounded-lg text-xs font-medium flex items-center space-x-1.5 cursor-pointer transition-colors ${
                  auditSubView === 'docs'
                    ? 'bg-slate-800 text-white'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                <FileText className="w-3.5 h-3.5 text-emerald-400" />
                <span>Tài liệu Thiết kế (docs/*.md & OpenAPI)</span>
              </button>
            </div>

            {auditSubView === 'audit' && (
              <AuditTrail statusChanges={statusChanges} findings={findings} />
            )}

            {auditSubView === 'vulns' && (
              <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
                <div className="px-6 py-4 border-b border-slate-800">
                  <h3 className="text-sm font-semibold text-slate-100">
                    Bảng Vulnerability Cache (OSV / NVD CVE / CISA KEV / FIRST EPSS)
                  </h3>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Dữ liệu làm giàu xác định (Deterministic Enrichment) phục vụ mô hình chấm điểm rủi ro CARE.
                  </p>
                </div>
                <div className="overflow-x-auto">
                  <table className="w-full text-left border-collapse text-xs">
                    <thead>
                      <tr className="border-b border-slate-800 bg-slate-950/60 text-slate-400 uppercase text-[11px]">
                        <th className="py-3 px-4">Mã Định Danh (PK)</th>
                        <th className="py-3 px-4">Aliases</th>
                        <th className="py-3 px-4">CVSS v3.1</th>
                        <th className="py-3 px-4">EPSS (Xác suất)</th>
                        <th className="py-3 px-4">CISA KEV</th>
                        <th className="py-3 px-4">SSVC / Fixed Versions</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/70">
                      {vulnerabilities.map((v) => (
                        <tr key={v.id} className="hover:bg-slate-800/40">
                          <td className="py-3 px-4 font-mono font-semibold text-indigo-400">
                            {v.id}
                          </td>
                          <td className="py-3 px-4 font-mono text-slate-400">
                            {v.aliases.join(', ') || '—'}
                          </td>
                          <td className="py-3 px-4 font-mono tabular-nums text-slate-200">
                            {v.cvssScore ?? 'N/A'}{' '}
                            <span className="text-[10px] text-slate-500">
                              [{v.cvssSource}]
                            </span>
                          </td>
                          <td className="py-3 px-4 font-mono tabular-nums text-amber-300">
                            {((v.epss ?? 0) * 100).toFixed(1)}%
                          </td>
                          <td className="py-3 px-4 font-mono">
                            {v.kev ? (
                              <span className="text-rose-400 font-semibold">IN KEV (+15)</span>
                            ) : (
                              <span className="text-slate-500">No</span>
                            )}
                          </td>
                          <td className="py-3 px-4 font-mono text-slate-300 max-w-md">
                            SSVC: {v.ssvc || 'Track'} · Fix: {v.fixedVersions.join(', ')}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {auditSubView === 'docs' && <DocsViewer />}
          </div>
        )}
      </main>

      {/* Human Status Triage Modal */}
      {statusModalFinding && (
        <StatusChangeModal
          finding={statusModalFinding}
          defaultActor={userSession.email}
          teamId={selectedTeamContext}
          onClose={() => setStatusModalFinding(null)}
          onSuccess={handleStatusChangeSuccess}
        />
      )}

      {/* Guardrailed AI Advisor Drawer */}
      {aiDrawerFinding && (
        <AiAdvisorDrawer
          finding={aiDrawerFinding}
          onClose={() => setAiDrawerFinding(null)}
          onRecordAiOutput={handleRecordAiOutput}
        />
      )}
    </div>
  );
}
