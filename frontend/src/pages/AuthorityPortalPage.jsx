import React, { useState, useEffect } from 'react';
import {
  ShieldAlert, ShieldCheck, AlertTriangle, AlertOctagon, User,
  FileText, Search, Filter, RefreshCw, Eye, CheckCircle2,
  Clock, Building, Laptop, ArrowUpRight, Copy, Check,
  Sparkles, ExternalLink, MessageSquare, ChevronDown, ChevronUp,
  Download, Send, Edit3, X
} from 'lucide-react';
import { api } from '../api';

export default function AuthorityPortalPage() {
  const [activeView, setActiveView] = useState('malicious'); // 'malicious' or 'all-prompts'
  const [authorityRole, setAuthorityRole] = useState('Chief Information Security Officer (CISO) & SecOps Incident Response');

  // Data states
  const [loading, setLoading] = useState(true);
  const [incidents, setIncidents] = useState([]);
  const [prompts, setPrompts] = useState([]);
  const [stats, setStats] = useState({
    total_prompts: 50,
    malicious_attempts: 5,
  });

  // Filters & Search
  const [searchQuery, setSearchQuery] = useState('');
  const [departmentFilter, setDepartmentFilter] = useState('ALL');
  const [decisionFilter, setDecisionFilter] = useState('ALL');
  const [statusFilter, setStatusFilter] = useState('ALL');

  // Selected item for modal
  const [selectedIncident, setSelectedIncident] = useState(null);
  const [selectedPrompt, setSelectedPrompt] = useState(null);
  const [copiedId, setCopiedId] = useState(null);

  // Status update form inside modal
  const [newStatus, setNewStatus] = useState('');
  const [authorityNote, setAuthorityNote] = useState('');
  const [investigatorName, setInvestigatorName] = useState('Senior SecOps Investigator');
  const [updatingStatus, setUpdatingStatus] = useState(false);
  const [updateMessage, setUpdateMessage] = useState('');

  // Expandable prompt rows in all-prompts table
  const [expandedRow, setExpandedRow] = useState(null);

  const fetchData = async () => {
    setLoading(true);
    try {
      const [incidentsData, promptsResp, statsData] = await Promise.all([
        api.getIncidents(100),
        api.getAuthorityPrompts({
          limit: 100,
          department: departmentFilter !== 'ALL' ? departmentFilter : '',
          decision: decisionFilter !== 'ALL' ? decisionFilter : '',
          search: searchQuery,
        }),
        api.getAuthorityStats(),
      ]);

      setIncidents(incidentsData || []);
      setPrompts(promptsResp?.prompts || []);
      setStats({
        total_prompts: statsData?.total_prompts ?? (promptsResp?.prompts?.length || 50),
        malicious_attempts: statsData?.malicious_attempts ?? (incidentsData?.length || 5),
      });
    } catch (err) {
      console.error('Failed to fetch authority portal data:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, [departmentFilter, decisionFilter]);

  const handleSearchSubmit = (e) => {
    e.preventDefault();
    fetchData();
  };

  const handleUpdateIncidentStatus = async () => {
    if (!selectedIncident) return;
    setUpdatingStatus(true);
    setUpdateMessage('');

    try {
      const res = await api.updateIncident({
        incidentId: selectedIncident.id,
        status: newStatus || selectedIncident.status,
        notes: authorityNote.trim() ? `[${authorityRole}] ${authorityNote.trim()}` : '',
        investigator: investigatorName,
      });

      setUpdateMessage('Case status updated successfully.');
      setTimeout(() => setUpdateMessage(''), 3000);
      setAuthorityNote('');

      // Refresh list
      fetchData();

      // Update selected incident in view
      if (res.incident) {
        setSelectedIncident(res.incident);
      }
    } catch (err) {
      alert(`Failed to update status: ${err.message}`);
    } finally {
      setUpdatingStatus(false);
    }
  };

  const handleCopyReport = (inc) => {
    const reportText = `[OFFICIAL SECURITY INCIDENT DOSSIER - HIGHER AUTHORITY RECORD]
Incident ID: ${inc.id}
Status: ${inc.status}
Severity: ${(inc.severity || 'high').toUpperCase()}
Timestamp: ${inc.created_at}
Assigned Authority: ${inc.higher_authority || authorityRole}

--- EMPLOYEE (PERSON UNDER INVESTIGATION) ---
Name: ${inc.person_name}
Employee ID: ${inc.person_id}
Email: ${inc.person_email}
Department: ${inc.person_department}
Client IP: ${inc.client_ip}
Workstation: ${inc.client_workstation}

--- MALICIOUS TRIGGER DETECTED ---
Trigger Extract: ${inc.malicious_text}
Violating Rules: ${(inc.violating_rules || []).join(', ') || 'N/A'}
Gateway Decision: ${inc.decision} (Risk Score: ${inc.risk_priority}/100)

--- COMPLETE RAW PROMPT SUBMITTED BY EMPLOYEE ---
Authorized Task: ${inc.authorized_task}
Prompt Content:
${inc.complete_prompt}

--- AUTHORITY CASE NOTES ---
${inc.notes || 'No case notes recorded yet.'}
`;
    navigator.clipboard.writeText(reportText);
    setCopiedId(inc.id);
    setTimeout(() => setCopiedId(null), 2500);
  };

  const handleOpenIncidentModal = (inc) => {
    setSelectedIncident(inc);
    setNewStatus(inc.status);
    setAuthorityNote('');
    setUpdateMessage('');
  };

  // Filtered incidents
  const filteredIncidents = incidents.filter((inc) => {
    if (statusFilter !== 'ALL' && inc.status !== statusFilter) return false;
    if (departmentFilter !== 'ALL' && !inc.person_department?.toLowerCase().includes(departmentFilter.toLowerCase())) return false;
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      return (
        inc.person_name?.toLowerCase().includes(q) ||
        inc.person_id?.toLowerCase().includes(q) ||
        inc.complete_prompt?.toLowerCase().includes(q) ||
        inc.malicious_text?.toLowerCase().includes(q) ||
        inc.id?.toLowerCase().includes(q)
      );
    }
    return true;
  });

  const getStatusBadge = (status) => {
    switch (status) {
      case 'TRANSFERRED_FOR_INVESTIGATION':
        return { label: 'Transferred for Investigation', bg: 'bg-[#FDECEC]', text: 'text-[#C85858]', border: 'border-[#C8585833]' };
      case 'UNDER_INVESTIGATION':
        return { label: 'Under Active Investigation', bg: 'bg-[#FEF7EC]', text: 'text-[#C48A31]', border: 'border-[#C48A3133]' };
      case 'ACTION_TAKEN':
        return { label: 'Disciplinary Action Taken', bg: 'bg-purple-50', text: 'text-purple-700', border: 'border-purple-200' };
      case 'EVIDENCE_SEALED':
        return { label: 'Evidence Sealed (Legal Audit)', bg: 'bg-indigo-50', text: 'text-indigo-700', border: 'border-indigo-200' };
      case 'RESOLVED':
        return { label: 'Case Resolved', bg: 'bg-[#EBF5F0]', text: 'text-[#24866B]', border: 'border-[#24866B33]' };
      case 'FALSE_POSITIVE_CLEARED':
        return { label: 'False Positive Cleared', bg: 'bg-gray-100', text: 'text-gray-700', border: 'border-gray-200' };
      default:
        return { label: status || 'Pending Triage', bg: 'bg-gray-100', text: 'text-gray-700', border: 'border-gray-200' };
    }
  };

  const getDecisionBadge = (decision) => {
    switch (decision) {
      case 'ALLOW':
        return { label: 'ALLOW', bg: 'bg-[#EBF5F0]', text: 'text-[#24866B]', border: 'border-[#24866B33]' };
      case 'BLOCK':
        return { label: 'BLOCK', bg: 'bg-[#FDECEC]', text: 'text-[#C85858]', border: 'border-[#C8585833]' };
      case 'SANITIZE':
        return { label: 'SANITIZE', bg: 'bg-blue-50', text: 'text-blue-700', border: 'border-blue-200' };
      case 'ESCALATE':
        return { label: 'ESCALATE', bg: 'bg-[#FEF7EC]', text: 'text-[#C48A31]', border: 'border-[#C48A3133]' };
      default:
        return { label: decision, bg: 'bg-gray-100', text: 'text-gray-600', border: 'border-gray-200' };
    }
  };

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      {/* Top Authority Header & Scope Switcher */}
      <div className="bg-[#FFFFFF] border border-[#E5E9EF] rounded-xl p-5 shadow-xs flex flex-col lg:flex-row lg:items-center justify-between gap-4">
        <div className="flex items-center gap-3.5 min-w-0">
          <div className="w-10 h-10 rounded-xl bg-[#202631] text-white flex items-center justify-center shadow-xs shrink-0 ring-4 ring-[#202631]/5">
            <ShieldAlert className="w-5 h-5 text-amber-400" />
          </div>
          <div className="min-w-0">
            <div className="flex items-center gap-2.5 flex-wrap">
              <h1 className="text-base font-bold text-[#202631] tracking-tight">
                Authority Investigation & Security Portal
              </h1>
              <span className="inline-flex items-center px-2.5 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-red-100 text-red-700 border border-red-200 whitespace-nowrap shadow-2xs">
                Authorized Personnel Only
              </span>
            </div>
            <p className="text-xs text-[#687385] mt-1">
              Enterprise prompt oversight, forensic analysis of employee inputs, and escalated threat resolution.
            </p>
          </div>
        </div>

        {/* Authority Role Selector */}
        <div className="flex items-center gap-2.5 text-xs shrink-0 self-start lg:self-center">
          <label className="text-[11px] font-medium text-[#687385] shrink-0 whitespace-nowrap">
            Authority Profile:
          </label>
          <div className="relative">
            <select
              value={authorityRole}
              onChange={(e) => setAuthorityRole(e.target.value)}
              className="text-xs pl-3 pr-8 py-2 rounded-lg border border-[#E5E9EF] bg-[#F8F9FB] hover:bg-white text-[#202631] font-medium transition-colors focus:bg-white focus:outline-none focus:ring-1 focus:ring-[#4263A6] cursor-pointer appearance-none shadow-2xs max-w-[260px] sm:max-w-[320px] truncate"
            >
              <option value="Chief Information Security Officer (CISO) & SecOps Incident Response">
                Chief Information Security Officer (CISO) & SecOps
              </option>
              <option value="Corporate Security & Internal Affairs Forensics Team">
                Corporate Security & Internal Affairs Forensics
              </option>
              <option value="Executive Risk Committee & Human Resources Disciplinary Audit">
                Executive Risk Committee & HR Disciplinary Audit
              </option>
              <option value="Legal Compliance & AI Ethics Oversight Division">
                Legal Compliance & AI Ethics Oversight
              </option>
            </select>
            <ChevronDown className="w-3.5 h-3.5 text-[#687385] absolute right-2.5 top-1/2 -translate-y-1/2 pointer-events-none" />
          </div>
          <button
            type="button"
            onClick={fetchData}
            title="Refresh All Feeds"
            className="h-[34px] w-[34px] flex items-center justify-center border border-[#E5E9EF] rounded-lg bg-[#F8F9FB] hover:bg-white hover:border-[#CBD5E1] text-[#687385] hover:text-[#202631] transition-colors cursor-pointer shrink-0 shadow-2xs"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* KPI Cards Bar */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
        <div className="bg-[#FFFFFF] border border-[#E5E9EF] rounded-xl p-4 shadow-xs">
          <div className="text-[11px] font-medium text-[#687385] flex items-center justify-between">
            <span>Total Employee Prompts</span>
            <FileText className="w-4 h-4 text-[#4263A6]" />
          </div>
          <div className="text-2xl font-bold text-[#202631] mt-2 font-mono">
            {stats.total_prompts}
          </div>
          <div className="text-[10px] text-[#687385] mt-1">Monitored across internal enterprise applications</div>
        </div>

        <div className="bg-[#FFFFFF] border-2 border-[#C8585844] rounded-xl p-4 shadow-xs">
          <div className="text-[11px] font-medium text-[#C85858] flex items-center justify-between">
            <span>Malicious Prompt Attempts</span>
            <AlertOctagon className="w-4 h-4 text-[#C85858]" />
          </div>
          <div className="text-2xl font-bold text-[#C85858] mt-2 font-mono">
            {stats.malicious_attempts}
          </div>
          <div className="text-[10px] text-[#C85858] mt-1 font-medium">Automatically reported directly to authority</div>
        </div>
      </div>

      {/* Primary Section Switcher Tabs */}
      <div className="flex border-b border-[#E5E9EF] gap-4 text-xs font-medium">
        <button
          type="button"
          onClick={() => setActiveView('malicious')}
          className={`pb-3 px-2 flex items-center gap-2 cursor-pointer transition-colors relative ${
            activeView === 'malicious'
              ? 'text-[#C85858] font-bold border-b-2 border-[#C85858]'
              : 'text-[#687385] hover:text-[#202631]'
          }`}
        >
          <AlertOctagon className="w-4 h-4" />
          <span>🚨 Malicious Employee Prompt Attempts & Escalations ({filteredIncidents.length})</span>
          <span className="px-1.5 py-0.2 rounded text-[10px] bg-[#FDECEC] text-[#C85858] border border-[#C8585833] font-bold">
            Priority Triage
          </span>
        </button>

        <button
          type="button"
          onClick={() => setActiveView('all-prompts')}
          className={`pb-3 px-2 flex items-center gap-2 cursor-pointer transition-colors relative ${
            activeView === 'all-prompts'
              ? 'text-[#4263A6] font-bold border-b-2 border-[#4263A6]'
              : 'text-[#687385] hover:text-[#202631]'
          }`}
        >
          <FileText className="w-4 h-4" />
          <span>📋 Organization Employee Prompts Feed ({prompts.length})</span>
        </button>
      </div>

      {/* Filter and Search Bar */}
      <div className="bg-[#FFFFFF] border border-[#E5E9EF] rounded-xl p-3 shadow-xs flex flex-wrap items-center justify-between gap-3 text-xs">
        <form onSubmit={handleSearchSubmit} className="flex-1 min-w-[240px] flex items-center gap-2">
          <div className="relative flex-1">
            <Search className="w-3.5 h-3.5 text-[#687385] absolute left-2.5 top-2.5" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search by employee name, employee ID, prompt text, or incident ID..."
              className="w-full text-xs pl-8 pr-3 py-1.5 rounded-lg border border-[#E5E9EF] bg-[#F8F9FB] text-[#202631] focus:bg-white focus:outline-none focus:ring-1 focus:ring-[#4263A6]"
            />
          </div>
          <button
            type="submit"
            className="px-3 py-1.5 bg-[#4263A6] text-white rounded-lg font-medium hover:bg-[#34518C] cursor-pointer"
          >
            Search
          </button>
        </form>

        <div className="flex flex-wrap items-center gap-2 text-xs">
          {/* Department Filter */}
          <div className="flex items-center gap-1.5">
            <span className="text-[#687385] text-[11px]">Dept:</span>
            <select
              value={departmentFilter}
              onChange={(e) => setDepartmentFilter(e.target.value)}
              className="px-2.5 py-1.5 rounded-lg border border-[#E5E9EF] bg-[#F8F9FB] text-[#202631] text-xs focus:bg-white"
            >
              <option value="ALL">All Departments</option>
              <option value="Finance">Finance & Commercial Ops</option>
              <option value="Engineering">Engineering</option>
              <option value="Legal">Legal & Compliance</option>
              <option value="IT Operations">IT Operations & DevOps</option>
              <option value="Human Resources">Human Resources</option>
              <option value="Product">Product Management</option>
            </select>
          </div>

          {/* Status Filter for Malicious view */}
          {activeView === 'malicious' ? (
            <div className="flex items-center gap-1.5">
              <span className="text-[#687385] text-[11px]">Status:</span>
              <select
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
                className="px-2.5 py-1.5 rounded-lg border border-[#E5E9EF] bg-[#F8F9FB] text-[#202631] text-xs focus:bg-white"
              >
                <option value="ALL">All Statuses</option>
                <option value="TRANSFERRED_FOR_INVESTIGATION">Transferred for Investigation</option>
                <option value="UNDER_INVESTIGATION">Under Active Investigation</option>
                <option value="ACTION_TAKEN">Disciplinary Action Taken</option>
                <option value="EVIDENCE_SEALED">Evidence Sealed</option>
                <option value="RESOLVED">Resolved</option>
              </select>
            </div>
          ) : (
            <div className="flex items-center gap-1.5">
              <span className="text-[#687385] text-[11px]">Verdict:</span>
              <select
                value={decisionFilter}
                onChange={(e) => setDecisionFilter(e.target.value)}
                className="px-2.5 py-1.5 rounded-lg border border-[#E5E9EF] bg-[#F8F9FB] text-[#202631] text-xs focus:bg-white"
              >
                <option value="ALL">All Decisions</option>
                <option value="ALLOW">ALLOW</option>
                <option value="BLOCK">BLOCK</option>
                <option value="SANITIZE">SANITIZE</option>
                <option value="ESCALATE">ESCALATE</option>
              </select>
            </div>
          )}
        </div>
      </div>

      {/* SECTION 1: MALICIOUS ATTEMPTS & ESCALATIONS */}
      {activeView === 'malicious' && (
        <div className="space-y-4">
          <div className="bg-[#FEF7EC] border border-[#C48A3133] rounded-xl p-4 text-xs text-[#C48A31] flex items-center justify-between">
            <div className="flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-[#C48A31] shrink-0" />
              <span>
                <strong>Authority Action Queue:</strong> The following employees submitted prompts that violated security policies. Every malicious attempt is automatically reported directly to your authority for immediate triage and forensic review.
              </span>
            </div>
            <span className="font-mono font-bold text-xs shrink-0 px-2 py-0.5 bg-white/60 rounded border border-[#C48A3133]">
              {filteredIncidents.length} Flagged Case(s)
            </span>
          </div>

          {filteredIncidents.length === 0 ? (
            <div className="bg-[#FFFFFF] border border-[#E5E9EF] rounded-xl p-12 text-center text-xs text-[#687385] space-y-2">
              <ShieldCheck className="w-8 h-8 text-[#24866B] mx-auto" />
              <div className="font-semibold text-[#202631]">No malicious incidents match your filter</div>
              <p>Try resetting filters or search queries to see all flagged prompts.</p>
            </div>
          ) : (
            <div className="space-y-4">
              {filteredIncidents.map((inc) => {
                const statusBadge = getStatusBadge(inc.status);
                const isCritical = inc.severity === 'critical';

                return (
                  <div
                    key={inc.id}
                    className="bg-[#FFFFFF] border-2 border-[#C8585833] rounded-xl p-5 shadow-xs space-y-4 hover:border-[#C8585866] transition-all"
                  >
                    {/* Header Row: Incident ID, Status Badge, Authority, Timestamp */}
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-[#E5E9EF] pb-3">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="font-mono font-bold text-xs px-2 py-0.5 bg-gray-100 border border-gray-300 rounded text-[#202631]">
                          {inc.id}
                        </span>
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider border ${statusBadge.bg} ${statusBadge.text} ${statusBadge.border}`}
                        >
                          {statusBadge.label}
                        </span>
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${isCritical ? 'bg-red-600 text-white' : 'bg-amber-600 text-white'}`}>
                          {inc.severity?.toUpperCase() || 'HIGH'} SEVERITY
                        </span>
                      </div>

                      <div className="text-[11px] text-[#687385] flex items-center gap-2">
                        <Clock className="w-3.5 h-3.5" />
                        <span>{new Date(inc.created_at).toLocaleString()}</span>
                      </div>
                    </div>

                    {/* Employee Identity Telemetry Grid */}
                    <div className="p-3.5 bg-[#F8F9FB] border border-[#E5E9EF] rounded-lg text-xs grid grid-cols-1 md:grid-cols-3 gap-3">
                      <div>
                        <div className="text-[10px] uppercase font-semibold text-[#687385] tracking-wider mb-1">
                          Employee (Offender)
                        </div>
                        <div className="font-bold text-[#202631] text-xs flex items-center gap-1.5">
                          <User className="w-3.5 h-3.5 text-[#4263A6]" />
                          {inc.person_name} ({inc.person_id})
                        </div>
                        <div className="text-[11px] text-[#687385] mt-0.5">{inc.person_email}</div>
                      </div>

                      <div>
                        <div className="text-[10px] uppercase font-semibold text-[#687385] tracking-wider mb-1">
                          Department & Role
                        </div>
                        <div className="font-medium text-[#202631] flex items-center gap-1.5 text-xs">
                          <Building className="w-3.5 h-3.5 text-[#24866B]" />
                          {inc.person_department}
                        </div>
                        <div className="text-[11px] text-[#687385] mt-0.5">
                          Claimed Task: <span className="font-mono font-medium">"{inc.authorized_task}"</span>
                        </div>
                      </div>

                      <div>
                        <div className="text-[10px] uppercase font-semibold text-[#687385] tracking-wider mb-1">
                          Endpoint & Station
                        </div>
                        <div className="font-mono text-xs text-[#202631] flex items-center gap-1.5">
                          <Laptop className="w-3.5 h-3.5 text-indigo-600" />
                          {inc.client_ip} • {inc.client_workstation}
                        </div>
                        <div className="text-[11px] text-[#687385] mt-0.5 font-mono">
                          Risk Priority Score: <span className="font-bold text-[#C85858]">{inc.risk_priority}/100</span>
                        </div>
                      </div>
                    </div>

                    {/* DIRECT VIEW OF WHAT PROMPT THE EMPLOYEE GAVE */}
                    <div className="space-y-1.5">
                      <div className="text-[11px] font-bold text-[#202631] flex items-center justify-between">
                        <span className="flex items-center gap-1.5">
                          <MessageSquare className="w-3.5 h-3.5 text-[#C85858]" />
                          Direct View: What Prompt Did That Employee Submit?
                        </span>
                        <span className="text-[10px] font-mono text-[#687385]">
                          Full Raw Text ({inc.complete_prompt.length} chars)
                        </span>
                      </div>
                      <div className="p-3 bg-[#FDECEC22] border-2 border-[#C8585844] rounded-lg font-mono text-xs text-[#202631] leading-relaxed whitespace-pre-wrap select-text break-words">
                        {inc.complete_prompt}
                      </div>
                    </div>

                    {/* Malicious Trigger Breakdown */}
                    <div className="p-3 bg-red-50/50 border border-red-200 rounded-lg text-xs space-y-1">
                      <div className="font-semibold text-[#C85858] flex items-center gap-1.5 text-[11px]">
                        <AlertOctagon className="w-3.5 h-3.5" />
                        Exact Malicious Text Trigger Detected:
                      </div>
                      <div className="font-mono text-xs font-bold text-[#C85858] bg-white p-2 rounded border border-red-200">
                        "{inc.malicious_text}"
                      </div>
                      <div className="text-[11px] text-[#687385] flex items-center gap-2 pt-1">
                        <span>Violated Policies:</span>
                        {(inc.violating_rules || []).map((r, i) => (
                          <span key={i} className="px-1.5 py-0.5 bg-white border border-[#E5E9EF] rounded font-mono text-[10px] text-[#202631]">
                            {r}
                          </span>
                        ))}
                      </div>
                    </div>

                    {/* Authority Case Notes if present */}
                    {inc.notes && (
                      <div className="p-3 bg-blue-50/50 border border-blue-200 rounded-lg text-xs space-y-1">
                        <div className="font-semibold text-blue-900 text-[11px] flex items-center gap-1.5">
                          <Edit3 className="w-3.5 h-3.5" />
                          Authority Investigation Log:
                        </div>
                        <p className="text-[11px] text-blue-950 font-sans whitespace-pre-wrap">{inc.notes}</p>
                      </div>
                    )}

                    {/* Bottom Action Controls */}
                    <div className="flex flex-wrap items-center justify-between gap-2 pt-2 border-t border-[#E5E9EF] text-xs">
                      <span className="text-[11px] text-[#687385]">
                        Assigned To: <strong className="text-[#202631]">{inc.higher_authority || authorityRole}</strong>
                      </span>

                      <div className="flex items-center gap-2">
                        <button
                          type="button"
                          onClick={() => handleCopyReport(inc)}
                          className="px-3 py-1.5 rounded-lg border border-[#E5E9EF] bg-white hover:bg-[#F8F9FB] text-[#202631] font-medium flex items-center gap-1.5 cursor-pointer text-xs transition-colors"
                        >
                          {copiedId === inc.id ? (
                            <>
                              <Check className="w-3.5 h-3.5 text-[#24866B]" />
                              <span className="text-[#24866B]">Dossier Copied!</span>
                            </>
                          ) : (
                            <>
                              <Copy className="w-3.5 h-3.5 text-[#687385]" />
                              <span>Copy Dossier</span>
                            </>
                          )}
                        </button>

                        <button
                          type="button"
                          onClick={() => handleOpenIncidentModal(inc)}
                          className="px-3.5 py-1.5 rounded-lg bg-[#202631] hover:bg-black text-white font-medium flex items-center gap-1.5 cursor-pointer text-xs transition-colors shadow-xs"
                        >
                          <Eye className="w-3.5 h-3.5" />
                          <span>Inspect & Update Case</span>
                        </button>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* SECTION 2: ALL ORGANIZATION EMPLOYEE PROMPTS FEED */}
      {activeView === 'all-prompts' && (
        <div className="bg-[#FFFFFF] border border-[#E5E9EF] rounded-xl shadow-xs overflow-hidden">
          <div className="p-4 border-b border-[#E5E9EF] flex items-center justify-between">
            <div>
              <h2 className="text-xs font-bold text-[#202631]">Organization Employee Prompts Log</h2>
              <p className="text-[11px] text-[#687385]">Real-time audit log of all prompts entered by people across departments.</p>
            </div>
            <span className="text-xs font-mono font-medium text-[#687385]">
              Showing {prompts.length} records
            </span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-xs text-left">
              <thead className="bg-[#F8F9FB] text-[#687385] text-[10px] uppercase tracking-wider border-b border-[#E5E9EF]">
                <tr>
                  <th className="py-2.5 px-3 font-semibold">Timestamp</th>
                  <th className="py-2.5 px-3 font-semibold">Employee</th>
                  <th className="py-2.5 px-3 font-semibold">Department</th>
                  <th className="py-2.5 px-3 font-semibold">Claimed Task</th>
                  <th className="py-2.5 px-3 font-semibold">Prompt Snippet</th>
                  <th className="py-2.5 px-3 font-semibold text-center">Verdict</th>
                  <th className="py-2.5 px-3 font-semibold text-center">Risk Score</th>
                  <th className="py-2.5 px-3 font-semibold text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#E5E9EF]">
                {prompts.map((p, idx) => {
                  const decisionBadge = getDecisionBadge(p.decision);
                  const isExpanded = expandedRow === p.id;

                  return (
                    <React.Fragment key={p.id || idx}>
                      <tr className={`hover:bg-[#F8F9FB] transition-colors ${p.is_malicious_attempt ? 'bg-[#FDECEC11]' : ''}`}>
                        <td className="py-2.5 px-3 font-mono text-[11px] text-[#687385] whitespace-nowrap">
                          {new Date(p.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                        </td>
                        <td className="py-2.5 px-3 font-medium text-[#202631]">
                          <div className="flex items-center gap-1.5">
                            <span className="w-5 h-5 rounded-full bg-[#E5E9EF] flex items-center justify-center text-[10px] font-bold text-[#202631]">
                              {p.person?.name?.charAt(0) || 'U'}
                            </span>
                            <div>
                              <div>{p.person?.name}</div>
                              <div className="text-[10px] text-[#687385] font-mono">{p.person?.employee_id}</div>
                            </div>
                          </div>
                        </td>
                        <td className="py-2.5 px-3 text-[#687385] text-[11px]">
                          {p.person?.department}
                        </td>
                        <td className="py-2.5 px-3 text-[#202631] font-medium max-w-[150px] truncate" title={p.task}>
                          {p.task}
                        </td>
                        <td className="py-2.5 px-3 font-mono text-[11px] text-[#202631] max-w-[280px] truncate" title={p.raw_content}>
                          {p.raw_content}
                        </td>
                        <td className="py-2.5 px-3 text-center whitespace-nowrap">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider border ${decisionBadge.bg} ${decisionBadge.text} ${decisionBadge.border}`}
                          >
                            {decisionBadge.label}
                          </span>
                        </td>
                        <td className="py-2.5 px-3 text-center font-mono font-bold text-[11px]">
                          <span className={p.risk_priority > 60 ? 'text-[#C85858]' : p.risk_priority > 30 ? 'text-amber-600' : 'text-[#24866B]'}>
                            {p.risk_priority}/100
                          </span>
                        </td>
                        <td className="py-2.5 px-3 text-right whitespace-nowrap">
                          <button
                            type="button"
                            onClick={() => setExpandedRow(isExpanded ? null : p.id)}
                            className="px-2 py-1 rounded bg-[#F8F9FB] border border-[#E5E9EF] hover:bg-gray-100 text-[#4263A6] font-medium text-[11px] cursor-pointer inline-flex items-center gap-1"
                          >
                            <span>{isExpanded ? 'Hide' : 'Inspect'}</span>
                            {isExpanded ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
                          </button>
                        </td>
                      </tr>

                      {/* Expandable row detail showing complete prompt */}
                      {isExpanded && (
                        <tr className="bg-[#F8F9FB]">
                          <td colSpan={8} className="p-4 space-y-3 border-t border-b border-[#E5E9EF]">
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                              <div className="space-y-1">
                                <div className="font-semibold text-[#202631] flex items-center justify-between text-[11px]">
                                  <span>Full Unedited Prompt Submitted by {p.person?.name}:</span>
                                  <span className="font-mono text-[10px] text-[#687385]">{p.raw_content.length} characters</span>
                                </div>
                                <div className="p-3 bg-white border border-[#E5E9EF] rounded-lg font-mono text-xs text-[#202631] leading-relaxed whitespace-pre-wrap break-words max-h-48 overflow-y-auto">
                                  {p.raw_content}
                                </div>
                              </div>

                              <div className="space-y-2">
                                <div className="font-semibold text-[#202631] text-[11px]">Gateway Assessment & Explanation:</div>
                                <div className="p-3 bg-white border border-[#E5E9EF] rounded-lg text-xs space-y-1.5">
                                  <div className="text-[11px] text-[#687385] leading-relaxed">
                                    {p.summary_explanation}
                                  </div>
                                  <div className="pt-2 border-t border-[#E5E9EF] text-[10px] text-[#687385] flex flex-wrap items-center gap-2">
                                    <span>Client IP: <strong className="text-[#202631] font-mono">{p.person?.client_ip}</strong></span>
                                    <span>•</span>
                                    <span>Workstation: <strong className="text-[#202631] font-mono">{p.person?.workstation}</strong></span>
                                    <span>•</span>
                                    <span>Inspection ID: <strong className="text-[#202631] font-mono">{p.id}</strong></span>
                                  </div>
                                </div>
                              </div>
                            </div>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* MODAL: COMPLETE FORENSIC INCIDENT INVESTIGATION DOSSIER */}
      {selectedIncident && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50 backdrop-blur-xs">
          <div className="bg-white rounded-2xl border border-[#E5E9EF] shadow-2xl max-w-3xl w-full max-h-[90vh] flex flex-col overflow-hidden animate-in fade-in duration-200">
            {/* Modal Header */}
            <div className="p-5 border-b border-[#E5E9EF] flex items-center justify-between bg-[#F8F9FB]">
              <div className="flex items-center gap-2.5">
                <div className="w-8 h-8 rounded-lg bg-[#202631] text-white flex items-center justify-center">
                  <ShieldAlert className="w-4 h-4 text-amber-400" />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <h2 className="text-sm font-bold text-[#202631]">Official Incident Forensic Dossier</h2>
                    <span className="font-mono text-xs px-2 py-0.5 bg-white border border-gray-300 rounded font-bold text-[#202631]">
                      {selectedIncident.id}
                    </span>
                  </div>
                  <p className="text-[11px] text-[#687385]">
                    Transferred to: {selectedIncident.higher_authority || authorityRole}
                  </p>
                </div>
              </div>
              <button
                type="button"
                onClick={() => setSelectedIncident(null)}
                className="p-1 rounded-lg text-[#687385] hover:text-[#202631] hover:bg-gray-200 cursor-pointer"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Modal Body */}
            <div className="p-6 overflow-y-auto space-y-5 text-xs">
              {/* Offender Identity Card */}
              <div className="p-4 bg-[#F8F9FB] border border-[#E5E9EF] rounded-xl space-y-2">
                <div className="text-[11px] font-bold text-[#202631] flex items-center gap-1.5 uppercase tracking-wider">
                  <User className="w-3.5 h-3.5 text-[#4263A6]" />
                  Person Under Investigation (Employee Details)
                </div>
                <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 text-[11px] text-[#687385]">
                  <div>Name: <strong className="text-[#202631]">{selectedIncident.person_name}</strong></div>
                  <div>Employee ID: <strong className="text-[#202631] font-mono">{selectedIncident.person_id}</strong></div>
                  <div>Email: <strong className="text-[#202631]">{selectedIncident.person_email}</strong></div>
                  <div>Department: <strong className="text-[#202631]">{selectedIncident.person_department}</strong></div>
                  <div>Client IP: <strong className="text-[#202631] font-mono">{selectedIncident.client_ip}</strong></div>
                  <div>Workstation: <strong className="text-[#202631] font-mono">{selectedIncident.client_workstation}</strong></div>
                </div>
              </div>

              {/* Exact Complete Prompt Submitted */}
              <div className="space-y-1.5">
                <div className="text-[11px] font-bold text-[#202631] flex items-center justify-between">
                  <span className="flex items-center gap-1.5 text-[#C85858]">
                    <AlertOctagon className="w-3.5 h-3.5" />
                    Complete Unedited Prompt Submitted by {selectedIncident.person_name}:
                  </span>
                  <span className="text-[10px] font-mono text-[#687385]">
                    Task: "{selectedIncident.authorized_task}"
                  </span>
                </div>
                <div className="p-3.5 bg-[#FDECEC22] border-2 border-[#C8585844] rounded-xl font-mono text-xs text-[#202631] leading-relaxed whitespace-pre-wrap select-text break-words">
                  {selectedIncident.complete_prompt}
                </div>
              </div>

              {/* Isolated Malicious Trigger */}
              <div className="p-3.5 bg-red-50/60 border border-red-200 rounded-xl space-y-1.5">
                <div className="font-bold text-[#C85858] text-[11px]">
                  Exact Malicious Instruction Spans Causing Policy Violation:
                </div>
                <div className="font-mono text-xs font-bold text-[#C85858] bg-white p-2.5 rounded-lg border border-red-200">
                  "{selectedIncident.malicious_text}"
                </div>
                <div className="text-[11px] text-[#687385] flex items-center gap-2">
                  <span>Violating Rules:</span>
                  {(selectedIncident.violating_rules || []).map((r, i) => (
                    <span key={i} className="px-1.5 py-0.5 bg-white border border-[#E5E9EF] rounded font-mono text-[10px] text-[#202631]">
                      {r}
                    </span>
                  ))}
                  <span>• Decision: <strong className="text-[#C85858]">{selectedIncident.decision}</strong></span>
                </div>
              </div>

              {/* Investigation Status & Authority Notes Management */}
              <div className="p-4 bg-indigo-50/40 border border-indigo-100 rounded-xl space-y-3">
                <div className="font-bold text-indigo-950 text-xs flex items-center gap-1.5">
                  <Edit3 className="w-3.5 h-3.5 text-indigo-600" />
                  Authority Case Status & Disciplinary Notes
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div>
                    <label className="text-[11px] font-semibold text-[#202631] block mb-1">
                      Update Investigation Status:
                    </label>
                    <select
                      value={newStatus}
                      onChange={(e) => setNewStatus(e.target.value)}
                      className="w-full text-xs px-3 py-1.5 rounded-lg border border-[#E5E9EF] bg-white text-[#202631]"
                    >
                      <option value="TRANSFERRED_FOR_INVESTIGATION">Transferred for Investigation</option>
                      <option value="UNDER_INVESTIGATION">Under Active Investigation</option>
                      <option value="ACTION_TAKEN">Disciplinary Action Taken</option>
                      <option value="EVIDENCE_SEALED">Evidence Sealed (Legal/Ethics Audit)</option>
                      <option value="RESOLVED">Case Resolved</option>
                      <option value="FALSE_POSITIVE_CLEARED">False Positive Cleared</option>
                    </select>
                  </div>

                  <div>
                    <label className="text-[11px] font-semibold text-[#202631] block mb-1">
                      Assigned Investigator:
                    </label>
                    <input
                      type="text"
                      value={investigatorName}
                      onChange={(e) => setInvestigatorName(e.target.value)}
                      className="w-full text-xs px-3 py-1.5 rounded-lg border border-[#E5E9EF] bg-white text-[#202631]"
                    />
                  </div>
                </div>

                <div>
                  <label className="text-[11px] font-semibold text-[#202631] block mb-1">
                    Add Authority Case Log / Disciplinary Note:
                  </label>
                  <textarea
                    rows={2}
                    value={authorityNote}
                    onChange={(e) => setAuthorityNote(e.target.value)}
                    placeholder="e.g. Conducted interview with employee. Verified intent was exploratory testing. Security awareness refresher course mandated."
                    className="w-full text-xs p-2.5 rounded-lg border border-[#E5E9EF] bg-white text-[#202631]"
                  />
                </div>

                {updateMessage && (
                  <div className="text-[11px] text-emerald-600 font-semibold">{updateMessage}</div>
                )}

                <div className="flex justify-end gap-2 pt-1">
                  <button
                    type="button"
                    onClick={handleUpdateIncidentStatus}
                    disabled={updatingStatus}
                    className="px-4 py-1.5 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg font-medium cursor-pointer disabled:opacity-50 text-xs shadow-xs"
                  >
                    {updatingStatus ? 'Saving...' : 'Save Case Status & Notes'}
                  </button>
                </div>
              </div>
            </div>

            {/* Modal Footer */}
            <div className="p-4 border-t border-[#E5E9EF] bg-[#F8F9FB] flex items-center justify-between">
              <button
                type="button"
                onClick={() => handleCopyReport(selectedIncident)}
                className="px-3 py-1.5 rounded-lg border border-[#E5E9EF] bg-white hover:bg-gray-100 text-[#202631] font-medium flex items-center gap-1.5 cursor-pointer text-xs"
              >
                {copiedId === selectedIncident.id ? (
                  <>
                    <Check className="w-3.5 h-3.5 text-[#24866B]" />
                    <span className="text-[#24866B]">Dossier Copied!</span>
                  </>
                ) : (
                  <>
                    <Copy className="w-3.5 h-3.5 text-[#687385]" />
                    <span>Copy Complete Legal Dossier</span>
                  </>
                )}
              </button>

              <button
                type="button"
                onClick={() => setSelectedIncident(null)}
                className="px-4 py-1.5 rounded-lg bg-gray-200 hover:bg-gray-300 text-[#202631] font-medium cursor-pointer text-xs"
              >
                Close Dossier
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
