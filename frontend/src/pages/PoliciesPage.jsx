import React, { useState, useEffect } from 'react';
import { Shield, Lock, Sliders, CheckCircle2, AlertTriangle, RefreshCw, Save } from 'lucide-react';
import { api } from '../api';

export default function PoliciesPage() {
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [saveSuccess, setSaveSuccess] = useState(false);
  const [error, setError] = useState(null);

  const [policyData, setPolicyData] = useState(null);
  const [settings, setSettings] = useState({
    enable_sanitization: true,
    enable_deep_decoding: true,
    escalate_uncertain_cases: true,
    escalate_threshold_drift: 75,
    policy_version: 'v2.1',
  });

  const loadPolicies = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.getPolicies();
      setPolicyData(data);
      if (data.settings) {
        setSettings((prev) => ({ ...prev, ...data.settings }));
      }
    } catch (err) {
      setError(err.message || 'Failed to fetch active policies.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadPolicies();
  }, []);

  const handleSettingToggle = (key) => {
    setSettings((prev) => ({ ...prev, [key]: !prev[key] }));
    setSaveSuccess(false);
  };

  const handleSliderChange = (e) => {
    setSettings((prev) => ({ ...prev, escalate_threshold_drift: parseInt(e.target.value) }));
    setSaveSuccess(false);
  };

  const handleSave = async () => {
    setSaving(true);
    setError(null);
    setSaveSuccess(false);

    try {
      const res = await api.updatePolicies(settings, settings.policy_version);
      if (res.status === 'success') {
        setSaveSuccess(true);
        setTimeout(() => setSaveSuccess(false), 4000);
      }
    } catch (err) {
      setError(err.message || 'Failed to save policies.');
    } finally {
      setSaving(false);
    }
  };

  if (loading) {
    return (
      <div className="p-12 text-center text-xs text-[#687385] flex items-center justify-center gap-2">
        <RefreshCw className="w-4 h-4 animate-spin text-[#4263A6]" />
        <span>Loading security policies...</span>
      </div>
    );
  }

  const hardRules = policyData?.policies?.filter((p) => p.is_hard_rule) || [];
  const configurableRules = policyData?.policies?.filter((p) => !p.is_hard_rule) || [];

  return (
    <div className="p-8 max-w-5xl mx-auto space-y-8">
      {/* Header controls & status banner */}
      <div className="flex items-center justify-between">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-xs font-semibold text-[#202631]">Policy Schema: {settings.policy_version}</span>
            <span className="text-[11px] font-medium text-[#24866B] bg-[#EBF5F0] px-2 py-0.5 rounded border border-[#24866B33]">
              Active & Enforced
            </span>
          </div>
          <p className="text-xs text-[#687385] mt-0.5">
            Deterministic security policies enforced on all incoming content.
          </p>
        </div>

        <button
          onClick={handleSave}
          disabled={saving}
          className="px-4 py-2 rounded-lg bg-[#4263A6] hover:bg-[#34518C] text-white text-xs font-medium flex items-center gap-1.5 transition-colors cursor-pointer shadow-xs disabled:opacity-50"
        >
          {saving ? (
            <>
              <RefreshCw className="w-3.5 h-3.5 animate-spin" />
              <span>Saving Changes...</span>
            </>
          ) : (
            <>
              <Save className="w-3.5 h-3.5" />
              <span>Save Policy Changes</span>
            </>
          )}
        </button>
      </div>

      {saveSuccess && (
        <div className="p-3 bg-[#EBF5F0] border border-[#24866B33] rounded-lg text-xs text-[#24866B] flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4 shrink-0" />
          <span>Security policy configuration successfully updated and verified by backend.</span>
        </div>
      )}

      {error && (
        <div className="p-3 bg-[#FDECEC] border border-[#C8585833] rounded-lg text-xs text-[#C85858] flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* SECTION 1: INVIOLABLE HARD SECURITY INVARIANTS */}
      <div className="bg-[#FFFFFF] border border-[#E5E9EF] rounded-xl p-5 shadow-xs space-y-4">
        <div className="flex items-center justify-between border-b border-[#E5E9EF] pb-3">
          <div className="flex items-center gap-2">
            <Lock className="w-4 h-4 text-[#C85858]" />
            <h3 className="text-sm font-semibold text-[#202631]">Enforced Security Hard Rules</h3>
          </div>
          <span className="text-[10px] uppercase font-bold text-[#C85858] bg-[#FDECEC] px-2 py-0.5 rounded">
            Immutable Controls (Always Locked)
          </span>
        </div>
        <p className="text-xs text-[#687385] leading-relaxed">
          These rules represent core security invariants. They cannot be bypassed or disabled by any user prompt, untrusted document instruction, or reviewer override.
        </p>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-1">
          {hardRules.map((rule) => (
            <div
              key={rule.id}
              className="p-3 rounded-lg border border-[#E5E9EF] bg-[#F8F9FB] flex items-start justify-between gap-3 text-xs"
            >
              <div>
                <div className="flex items-center gap-2 font-semibold text-[#202631]">
                  <span>{rule.name}</span>
                  <span className="text-[10px] font-mono text-[#687385]">[{rule.rule_id}]</span>
                </div>
                <p className="text-[11px] text-[#687385] mt-1 leading-relaxed">{rule.description}</p>
                <div className="mt-2 text-[10px] font-bold text-[#C85858] uppercase">
                  Action: {rule.action} (Priority {rule.priority})
                </div>
              </div>
              <div className="w-6 h-6 rounded bg-[#FDECEC] text-[#C85858] flex items-center justify-center shrink-0">
                <Lock className="w-3.5 h-3.5" />
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* SECTION 2: CONFIGURABLE GATEWAY POLICIES */}
      <div className="bg-[#FFFFFF] border border-[#E5E9EF] rounded-xl p-5 shadow-xs space-y-5">
        <div className="border-b border-[#E5E9EF] pb-3">
          <div className="flex items-center gap-2">
            <Sliders className="w-4 h-4 text-[#4263A6]" />
            <h3 className="text-sm font-semibold text-[#202631]">Configurable Gateway Controls</h3>
          </div>
          <p className="text-xs text-[#687385] mt-0.5">
            Operational toggles and thresholds for adaptive inspection and sanitization handling.
          </p>
        </div>

        <div className="space-y-4 text-xs">
          {/* Toggle 1: Surgical Sanitization */}
          <div className="flex items-center justify-between p-3.5 rounded-lg border border-[#E5E9EF] bg-[#F8F9FB]">
            <div>
              <div className="font-semibold text-[#202631]">Enable Surgical Sanitization for Documents</div>
              <p className="text-[11px] text-[#687385] mt-0.5">
                When an untrusted document contains an isolated injection, excise the offending span and reinspect.
              </p>
            </div>
            <label className="relative inline-flex items-center cursor-pointer">
              <input
                type="checkbox"
                checked={settings.enable_sanitization}
                onChange={() => handleSettingToggle('enable_sanitization')}
                className="sr-only peer"
              />
              <div className="w-9 h-5 bg-[#D8DFE8] peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-[#4263A6]"></div>
            </label>
          </div>

          {/* Toggle 2: Deep Obfuscation Decoding */}
          <div className="flex items-center justify-between p-3.5 rounded-lg border border-[#E5E9EF] bg-[#F8F9FB]">
            <div>
              <div className="font-semibold text-[#202631]">Strict Base64 & Hex Bounded Decoding</div>
              <p className="text-[11px] text-[#687385] mt-0.5">
                Automatically inspect decoded payloads for hidden prompt overrides or token leaks.
              </p>
            </div>
            <label className="relative inline-flex items-center cursor-pointer">
              <input
                type="checkbox"
                checked={settings.enable_deep_decoding}
                onChange={() => handleSettingToggle('enable_deep_decoding')}
                className="sr-only peer"
              />
              <div className="w-9 h-5 bg-[#D8DFE8] peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-[#4263A6]"></div>
            </label>
          </div>

          {/* Toggle 3: Escalation for Uncertain Cases */}
          <div className="flex items-center justify-between p-3.5 rounded-lg border border-[#E5E9EF] bg-[#F8F9FB]">
            <div>
              <div className="font-semibold text-[#202631]">Human Review Escalation for High Uncertainty</div>
              <p className="text-[11px] text-[#687385] mt-0.5">
                Hold ambiguous administrative requests or degraded detector outputs for administrator sign-off.
              </p>
            </div>
            <label className="relative inline-flex items-center cursor-pointer">
              <input
                type="checkbox"
                checked={settings.escalate_uncertain_cases}
                onChange={() => handleSettingToggle('escalate_uncertain_cases')}
                className="sr-only peer"
              />
              <div className="w-9 h-5 bg-[#D8DFE8] peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-[#4263A6]"></div>
            </label>
          </div>

          {/* Slider: Drift Threshold */}
          <div className="p-3.5 rounded-lg border border-[#E5E9EF] bg-[#F8F9FB] space-y-2">
            <div className="flex items-center justify-between">
              <div>
                <div className="font-semibold text-[#202631]">Intent Drift Escalation Threshold</div>
                <p className="text-[11px] text-[#687385] mt-0.5">
                  Escalate inputs when content deviates significantly from authorized task intent.
                </p>
              </div>
              <span className="font-mono font-bold text-xs text-[#4263A6] bg-[#E8EEF8] px-2 py-0.5 rounded">
                {settings.escalate_threshold_drift}%
              </span>
            </div>
            <input
              type="range"
              min="50"
              max="95"
              step="5"
              value={settings.escalate_threshold_drift}
              onChange={handleSliderChange}
              className="w-full accent-[#4263A6] cursor-pointer"
            />
            <div className="flex justify-between text-[10px] text-[#687385]">
              <span>50% (Strict)</span>
              <span>75% (Recommended)</span>
              <span>95% (Permissive)</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
