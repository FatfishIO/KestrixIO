import React from 'react';

interface HeaderProps {
  activeTab: string;
  setActiveTab: (tab: string) => void;
}

export const Header: React.FC<HeaderProps> = ({ activeTab, setActiveTab }) => {
  const navLinks = [
    { id: 'findings', label: 'Findings' },
    { id: 'advisor', label: 'Pipeline & AI' },
    { id: 'scanners', label: 'Scan Ingest' },
    { id: 'assets', label: 'Assets & Teams' },
    { id: 'audit', label: 'Audit & Docs' },
  ];

  return (
    <header className="bg-slate-900 border-b border-slate-800 sticky top-0 z-30">
      <div className="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between gap-8">
        {/* Zone 1: Single text element Brand wordmark */}
        <button
          onClick={() => setActiveTab('findings')}
          className="text-lg font-bold tracking-tight text-slate-100 whitespace-nowrap shrink-0 cursor-pointer"
        >
          Kestrix
        </button>

        {/* Zone 2: 5 concise single-line text navigation links */}
        <nav className="flex items-center gap-6 text-sm font-medium overflow-x-auto scrollbar-none">
          {navLinks.map((link) => {
            const isActive =
              activeTab === link.id ||
              (link.id === 'audit' && activeTab === 'docs');
            return (
              <button
                key={link.id}
                onClick={() => setActiveTab(link.id)}
                className={`py-5 border-b-2 transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                  isActive
                    ? 'border-indigo-500 text-slate-100 font-semibold'
                    : 'border-transparent text-slate-400 hover:text-slate-200 hover:border-slate-700'
                }`}
              >
                {link.label}
              </button>
            );
          })}
        </nav>

        {/* Zone 3: 1 primary action */}
        <div className="flex items-center shrink-0">
          <button
            onClick={() => setActiveTab('scanners')}
            className="px-4 py-2 text-xs font-semibold text-white bg-indigo-600 rounded-lg hover:bg-indigo-500 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
          >
            Ingest Scan Report
          </button>
        </div>
      </div>
    </header>
  );
};
