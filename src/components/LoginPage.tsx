import React, { useState } from 'react';
import { Shield, Lock, ArrowRight, KeyRound, AlertCircle } from 'lucide-react';

export interface KestrixUserSession {
  email: string;
  name: string;
  role: 'secops_admin' | 'team_owner' | 'security_reviewer';
  teamId: string;
  teamName: string;
  sessionToken: string;
  authenticatedAt: string;
}

interface LoginPageProps {
  onLoginSuccess: (session: KestrixUserSession) => void;
}

const ACCOUNTS: Array<{
  email: string;
  password: string;
  name: string;
  role: KestrixUserSession['role'];
  teamId: string;
  teamName: string;
}> = [
  {
    email: 'secops@kestrix.local',
    password: 'test-secops-password',
    name: 'Global SecOps',
    role: 'secops_admin',
    teamId: 'all',
    teamName: 'All Teams',
  },
  {
    email: 'test-core@kestrix.local',
    password: 'test-core-password',
    name: 'Test Core Lead',
    role: 'team_owner',
    teamId: 'team-core',
    teamName: 'Core Security & Platform',
  },
  {
    email: 'test-pay@kestrix.local',
    password: 'test-pay-password',
    name: 'Test Payments Lead',
    role: 'team_owner',
    teamId: 'team-checkout',
    teamName: 'Payments & Checkout',
  },
];

export const LoginPage: React.FC<LoginPageProps> = ({ onLoginSuccess }) => {
  const [email, setEmail] = useState('secops@kestrix.local');
  const [password, setPassword] = useState('test-secops-password');
  const [selectedTeamId, setSelectedTeamId] = useState('all');
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  const selectAccount = (preset: (typeof ACCOUNTS)[number]) => {
    setEmail(preset.email);
    setPassword(preset.password);
    setSelectedTeamId(preset.teamId);
    setError(null);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setIsLoading(true);

    try {
      const response = await fetch('/api/v1/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: email.trim(),
          password,
          teamId: selectedTeamId,
        }),
      });

      if (response.ok) {
        const json = await response.json();
        if (json.data?.session) {
          onLoginSuccess(json.data.session);
          return;
        }
      } else {
        const errBody = await response.json();
        if (errBody.error?.message) {
          throw new Error(errBody.error.message);
        }
      }

      if (!password || password.length < 6) {
        throw new Error('Mật khẩu phải có tối thiểu 6 ký tự.');
      }

      const matched = ACCOUNTS.find(
        (acc) => acc.email.toLowerCase() === email.trim().toLowerCase()
      );

      onLoginSuccess({
        email: email.trim(),
        name: matched?.name || email.trim().split('@')[0],
        role: matched?.role || (selectedTeamId === 'all' ? 'secops_admin' : 'team_owner'),
        teamId: matched?.teamId || selectedTeamId,
        teamName: matched?.teamName || selectedTeamId,
        sessionToken: `kstx_sess_${Date.now().toString(36)}`,
        authenticatedAt: new Date().toISOString(),
      });
    } catch (err: any) {
      setError(err?.message || 'Đăng nhập thất bại.');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex items-center justify-center p-4">
      <div className="w-full max-w-md bg-slate-900 border border-slate-800 rounded-xl p-6 sm:p-8 shadow-xl space-y-6">
        <div className="flex items-center space-x-3 border-b border-slate-800 pb-4">
          <div className="w-9 h-9 rounded-lg bg-indigo-600/20 border border-indigo-500/40 flex items-center justify-center">
            <Shield className="w-5 h-5 text-indigo-400" />
          </div>
          <div>
            <h1 className="text-lg font-bold text-slate-100">Kestrix Console</h1>
            <p className="text-xs text-slate-400">Vulnerability Management & AI Triage</p>
          </div>
        </div>

        <div className="grid grid-cols-3 gap-2">
          {ACCOUNTS.map((acc) => {
            const active = email.toLowerCase() === acc.email.toLowerCase();
            return (
              <button
                key={acc.email}
                type="button"
                onClick={() => selectAccount(acc)}
                className={`p-2 rounded-lg border text-left transition-colors cursor-pointer ${
                  active
                    ? 'bg-indigo-950/50 border-indigo-500 text-slate-100'
                    : 'bg-slate-950 border-slate-800 text-slate-400 hover:border-slate-700 hover:text-slate-200'
                }`}
              >
                <div className="text-xs font-semibold truncate">{acc.name}</div>
                <div className="text-[10px] font-mono text-slate-500 truncate mt-0.5">
                  {acc.teamId}
                </div>
              </button>
            );
          })}
        </div>

        {error && (
          <div className="p-3 rounded-lg bg-rose-950/80 border border-rose-800 text-xs text-rose-200 flex items-start space-x-2">
            <AlertCircle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">Email</label>
            <input
              type="email"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-sm text-slate-100 font-mono focus:outline-none focus:border-indigo-500"
            />
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">Mật khẩu</label>
            <div className="relative">
              <input
                type="password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-sm text-slate-100 font-mono focus:outline-none focus:border-indigo-500"
              />
              <KeyRound className="w-4 h-4 text-slate-500 absolute right-3 top-2.5" />
            </div>
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">Team Scope</label>
            <select
              value={selectedTeamId}
              onChange={(e) => setSelectedTeamId(e.target.value)}
              className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-sm text-slate-200 focus:outline-none focus:border-indigo-500"
            >
              <option value="all">Global SecOps (All Teams)</option>
              <option value="team-core">team-core (Core Security & Platform)</option>
              <option value="team-checkout">team-checkout (Payments & Checkout)</option>
              <option value="team-mobile">team-mobile (Mobile Client Apps)</option>
            </select>
          </div>

          <button
            type="submit"
            disabled={isLoading}
            className="w-full py-2.5 px-4 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white text-sm font-semibold rounded-lg transition-colors flex items-center justify-center space-x-2 cursor-pointer"
          >
            <Lock className="w-4 h-4" />
            <span>{isLoading ? 'Đang xác thực...' : 'Đăng nhập'}</span>
            <ArrowRight className="w-4 h-4" />
          </button>
        </form>
      </div>
    </div>
  );
};
