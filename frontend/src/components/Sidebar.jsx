import React from 'react';
import { Shield, Search, FlaskConical, Sliders, BarChart3, Clock, CheckCircle2, AlertCircle, ShieldAlert } from 'lucide-react';

export default function Sidebar({ activeTab, setActiveTab, backendStatus }) {
  const navItems = [
    { id: 'inspector', label: 'Inspector', icon: Search, badge: 'Demo' },
    { id: 'authority', label: 'Authority Portal', icon: ShieldAlert, badge: 'SecOps' },
    { id: 'attack-lab', label: 'Attack Lab', icon: FlaskConical },
    { id: 'policies', label: 'Policies', icon: Sliders },
    { id: 'evaluation', label: 'Evaluation', icon: BarChart3 },
    { id: 'history', label: 'History', icon: Clock },
  ];

  return (
    <aside className="w-64 bg-[#F3F5F7] border-r border-[#E5E9EF] flex flex-col justify-between select-none h-screen sticky top-0 shrink-0">
      <div>
        {/* Brand Header */}
        <div className="p-5 border-b border-[#E5E9EF]">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-[#4263A6] text-white flex items-center justify-center shadow-xs">
              <Shield className="w-4 h-4" />
            </div>
            <div>
              <div className="text-sm font-semibold tracking-tight text-[#202631]">PromptShield X</div>
              <div className="text-[11px] text-[#687385] font-normal">Security Gateway v2.1</div>
            </div>
          </div>
        </div>

        {/* Navigation Links */}
        <nav className="p-3 space-y-1">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => setActiveTab(item.id)}
                className={`w-full flex items-center justify-between px-3 py-2 rounded-lg text-xs font-medium transition-colors ${
                  isActive
                    ? 'bg-[#FFFFFF] text-[#202631] shadow-xs border border-[#E5E9EF]'
                    : 'text-[#687385] hover:text-[#202631] hover:bg-[#EAEFF5]'
                }`}
              >
                <div className="flex items-center gap-2.5">
                  <Icon className={`w-4 h-4 ${isActive ? 'text-[#4263A6]' : 'text-[#687385]'}`} />
                  <span>{item.label}</span>
                </div>
                {item.badge && (
                  <span className="text-[10px] uppercase font-semibold tracking-wider px-1.5 py-0.5 rounded bg-[#E8EEF8] text-[#4263A6]">
                    {item.badge}
                  </span>
                )}
              </button>
            );
          })}
        </nav>
      </div>

      {/* Backend / Offline Engine Status Card */}
      <div className="p-4 border-t border-[#E5E9EF]">
        <div className="bg-[#FFFFFF] border border-[#E5E9EF] rounded-lg p-3 text-xs shadow-2xs">
          <div className="flex items-center justify-between mb-1">
            <span className="font-medium text-[#202631]">Gateway Engine</span>
            {backendStatus === 'online' ? (
              <span className="flex items-center gap-1 text-[11px] text-[#24866B] font-medium">
                <span className="w-2 h-2 rounded-full bg-[#24866B] animate-pulse"></span>
                Active
              </span>
            ) : (
              <span className="flex items-center gap-1 text-[11px] text-[#C85858] font-medium">
                <span className="w-2 h-2 rounded-full bg-[#C85858]"></span>
                Offline
              </span>
            )}
          </div>
          <p className="text-[11px] text-[#687385] leading-relaxed">
            Local TF-IDF + Logistic Regression offline pipeline. Zero cloud API dependencies.
          </p>
        </div>
      </div>
    </aside>
  );
}
