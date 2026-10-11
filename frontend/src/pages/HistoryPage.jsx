import React, { useState, useEffect } from 'react';
import {
  Search, Clock, ShieldCheck, AlertOctagon, FileText, X,
  ExternalLink, ChevronRight, RefreshCw, UserCheck, UserX, AlertTriangle
} from 'lucide-react';
import { api } from '../api';

export default function HistoryPage() {
  const [loading, setLoading] = useState(true);
  const [items, setItems] = useState([]);
  const [search, setSearch] = useState('');
  const [decisionFilter, setDecisionFilter] = useState('ALL');

  // Detail Modal / Drawer
  const [selectedId, setSelectedId] = useState(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detail, setDetail] = useState(null);

  // Review action state
  const [reviewActionLoading, setReviewActionLoading] = useState(false);

  const fetchHistory = async () => {
    setLoading(true);
    try {
      const data = await api.getHistory({
        limit: 50,
        search,
        decision: decisionFilter,
      });
      setItems(data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHistory();
  }, [decisionFilter]);

  const handleSearchSubmit = (e) => {
    e.preventDefault();
    fetchHistory();
  };

  const handleViewDetail = async (id) => {
    setSelectedId(id);
    setDetailLoading(true);
    setDetail(null);
    try {
      const d = await api.getInspectionDetails(id);
      setDetail(d);
    } catch (err) {
      alert(`Error loading inspection detail: ${err.message}`);
    } finally {
      setDetailLoading(false);
    }
  };

  const handleReviewAction = async (action) => {
    if (!detail) return;
    setReviewActionLoading(true);
    try {
      await api.submitReview({
        inspectionId: detail.inspection_id,
        action,
        reviewer: 'lead_evaluator',
        notes: `Judge review decision: ${action}`,
      });
      // Reload detail
      const refreshed = await api.getInspectionDetails(detail.inspection_id);
      setDetail(refreshed);
      fetchHistory();
    } catch (err) {
      alert(`Review action rejected: ${err.message}`);
    } finally {
      setReviewActionLoading(false);
    }
  };

  return (
    <div className="p-8 max-w-6xl mx-auto space-y-6">
      {/* Top Search & Filter Bar */}
      <div className="flex flex-col md:flex-row items-center justify-between gap-4">
        <form onSubmit={handleSearchSubmit} className="relative w-full md:w-96">
          <Search className="w-3.5 h-3.5 text-[#687385] absolute left-3 top-2.5" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search by ID, task description..."
            className="w-full text-xs pl-8 pr-3 py-2 rounded-lg border border-[#E5E9EF] bg-[#FFFFFF] text-[#202631] focus:outline-none focus:ring-1 focus:ring-[#4263A6] shadow-2xs"
          />
        </form>

        <div className="flex items-center gap-1.5 overflow-x-auto w-full md:w-auto text-xs">
          {['ALL', 'ALLOW', 'BLOCK', 'SANITIZE', 'ESCALATE'].map((d) => (
            <button
              key={d}
              onClick={() => setDecisionFilter(d)}
              className={`px-3 py-1.5 rounded-lg text-[11px] font-medium transition-colors cursor-pointer ${
                decisionFilter === d
                  ? 'bg-[#4263A6] text-white shadow-2xs'
                  : 'bg-[#FFFFFF] border border-[#E5E9EF] text-[#687385] hover:text-[#202631]'
              }`}
            >
              {d}
            </button>
          ))}
          <button
            onClick={fetchHistory}
            className="p-1.5 rounded-lg bg-[#FFFFFF] border border-[#E5E9EF] text-[#687385] hover:text-[#202631] shadow-2xs"
            title="Refresh"
          >
            <RefreshCw className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* History Table */}
      <div className="bg-[#FFFFFF] border border-[#E5E9EF] rounded-xl overflow-hidden shadow-xs">
        {loading ? (
          <div className="p-12 text-center text-xs text-[#687385] flex items-center justify-center gap-2">
            <RefreshCw className="w-4 h-4 animate-spin text-[#4263A6]" />
            <span>Loading past inspections...</span>
          </div>
        ) : items.length === 0 ? (
          <div className="p-12 text-center text-xs text-[#687385]">
            No inspection history records found.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="bg-[#F8F9FB] border-b border-[#E5E9EF] text-[#687385] font-medium text-[11px]">
                  <th className="py-3 px-4">Inspection ID</th>
                  <th className="py-3 px-4">Source</th>
                  <th className="py-3 px-4">Authorized Task</th>
                  <th className="py-3 px-4">Decision</th>
                  <th className="py-3 px-4">Risk Index</th>
                  <th className="py-3 px-4">Triggered Rules</th>
                  <th className="py-3 px-4">Timestamp</th>
                  <th className="py-3 px-4 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#E5E9EF]">
                {items.map((item) => (
                  <tr
                    key={item.inspection_id}
                    onClick={() => handleViewDetail(item.inspection_id)}
                    className="hover:bg-[#F8F9FB] cursor-pointer transition-colors"
                  >
                    <td className="py-3 px-4 font-mono font-medium text-[#202631]">
                      {item.inspection_id}
                    </td>
                    <td className="py-3 px-4 text-[11px] text-[#687385]">{item.source_type}</td>
                    <td className="py-3 px-4 text-[#202631] font-medium max-w-xs truncate">
                      {item.task}
                    </td>
                    <td className="py-3 px-4">
                      <span
                        className={`text-[10px] font-bold px-2 py-0.5 rounded ${
                          item.decision === 'ALLOW'
                            ? 'bg-[#EBF5F0] text-[#24866B]'
                            : item.decision === 'SANITIZE'
                            ? 'bg-[#E8EEF8] text-[#4263A6]'
                            : item.decision === 'ESCALATE'
                            ? 'bg-[#FEF7EC] text-[#C48A31]'
                            : 'bg-[#FDECEC] text-[#C85858]'
                        }`}
                      >
                        {item.decision}
                      </span>
                    </td>
                    <td className="py-3 px-4 font-mono text-[11px]">
                      {item.risk_scores?.combined_priority !== undefined ? (
                        <span>{item.risk_scores.combined_priority}/100</span>
                      ) : (
                        <span className="text-[#687385]">—</span>
                      )}
                    </td>
                    <td className="py-3 px-4 text-[11px] font-mono text-[#687385]">
                      {item.triggered_rules?.length > 0 ? (
                        <span className="text-[#C85858] font-semibold">
                          {item.triggered_rules.join(', ')}
                        </span>
                      ) : (
                        'None'
                      )}
                    </td>
                    <td className="py-3 px-4 text-[11px] text-[#687385]">
                      {item.created_at ? new Date(item.created_at).toLocaleTimeString() : '—'}
                    </td>
                    <td className="py-3 px-4 text-right">
                      <button className="text-[11px] text-[#4263A6] hover:underline font-medium inline-flex items-center gap-0.5">
                        Details <ChevronRight className="w-3 h-3" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Slide-over Inspection Detail Modal */}
      {selectedId && (
        <div className="fixed inset-0 bg-[#20263155] z-50 flex justify-end">
          <div className="w-full max-w-2xl bg-[#FFFFFF] h-full shadow-xl flex flex-col justify-between overflow-y-auto p-6 space-y-5 animate-in slide-in-from-right">
            <div>
              <div className="flex items-center justify-between border-b border-[#E5E9EF] pb-4">
                <div>
                  <div className="text-[11px] font-mono text-[#687385]">{selectedId}</div>
                  <h3 className="text-sm font-semibold text-[#202631] mt-0.5">Inspection Record</h3>
                </div>
                <button
                  onClick={() => setSelectedId(null)}
                  className="p-1 rounded-md text-[#687385] hover:bg-[#F3F5F7] cursor-pointer"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>

              {detailLoading || !detail ? (
                <div className="p-12 text-center text-xs text-[#687385] flex items-center justify-center gap-2">
                  <RefreshCw className="w-4 h-4 animate-spin text-[#4263A6]" />
                  <span>Loading full record...</span>
                </div>
              ) : (
                <div className="space-y-4 pt-4 text-xs">
                  {/* Status Banner */}
                  <div className="p-3.5 bg-[#F8F9FB] rounded-lg border border-[#E5E9EF] space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="font-semibold text-[#202631]">Decision: {detail.decision}</span>
                      <span className="text-[11px] text-[#687385]">
                        Forwarding: {detail.forwarding_permitted ? 'Permitted' : 'Blocked'}
                      </span>
                    </div>
                    <p className="text-[11px] text-[#687385] leading-relaxed">
                      {detail.summary_explanation}
                    </p>
                  </div>

                  {/* Masked Content View */}
                  <div>
                    <label className="block text-[11px] font-semibold text-[#687385] uppercase mb-1">
                      Stored Masked Content
                    </label>
                    <div className="p-3 bg-[#F8F9FB] border border-[#E5E9EF] rounded-lg font-mono text-[11px] text-[#202631] whitespace-pre-wrap leading-relaxed">
                      {detail.content}
                    </div>
                  </div>

                  {/* Risk Breakdown */}
                  {detail.risk_scores && (
                    <div className="p-3.5 bg-[#FFFFFF] border border-[#E5E9EF] rounded-lg space-y-2">
                      <div className="font-semibold text-[#202631] text-[11px] uppercase">Risk Indicators</div>
                      <div className="grid grid-cols-4 gap-2 text-center">
                        <div className="p-2 bg-[#F8F9FB] rounded border border-[#E5E9EF]">
                          <div className="text-[10px] text-[#687385]">Prompt</div>
                          <div className="font-bold text-[#202631]">{detail.risk_scores.prompt_risk}</div>
                        </div>
                        <div className="p-2 bg-[#F8F9FB] rounded border border-[#E5E9EF]">
                          <div className="text-[10px] text-[#687385]">Source</div>
                          <div className="font-bold text-[#202631]">{detail.risk_scores.source_risk}</div>
                        </div>
                        <div className="p-2 bg-[#F8F9FB] rounded border border-[#E5E9EF]">
                          <div className="text-[10px] text-[#687385]">Drift</div>
                          <div className="font-bold text-[#202631]">{detail.risk_scores.intent_drift_risk}</div>
                        </div>
                        <div className="p-2 bg-[#F8F9FB] rounded border border-[#E5E9EF]">
                          <div className="text-[10px] text-[#687385]">Impact</div>
                          <div className="font-bold text-[#202631]">{detail.risk_scores.action_impact}</div>
                        </div>
                      </div>
                    </div>
                  )}

                  {/* Human Review Controls (If ESCALATE) */}
                  {detail.decision === 'ESCALATE' && detail.review_status === 'none' && (
                    <div className="p-4 bg-[#FEF7EC] border border-[#C48A3133] rounded-lg space-y-3">
                      <div className="flex items-center gap-2 text-[#C48A31] font-semibold">
                        <AlertTriangle className="w-4 h-4" />
                        Pending Human Review Sign-Off
                      </div>
                      <p className="text-[11px] text-[#687385]">
                        This inspection was escalated. Reviewers may approve or reject execution. (Note: Hard token violations cannot be approved).
                      </p>
                      <div className="flex items-center gap-2 pt-1">
                        <button
                          onClick={() => handleReviewAction('APPROVE')}
                          disabled={reviewActionLoading}
                          className="px-3 py-1.5 rounded-lg bg-[#24866B] hover:bg-[#1C6954] text-white text-xs font-medium flex items-center gap-1 cursor-pointer"
                        >
                          <UserCheck className="w-3.5 h-3.5" />
                          <span>Approve & Permit</span>
                        </button>
                        <button
                          onClick={() => handleReviewAction('REJECT')}
                          disabled={reviewActionLoading}
                          className="px-3 py-1.5 rounded-lg bg-[#C85858] hover:bg-[#A84848] text-white text-xs font-medium flex items-center gap-1 cursor-pointer"
                        >
                          <UserX className="w-3.5 h-3.5" />
                          <span>Reject & Block</span>
                        </button>
                      </div>
                    </div>
                  )}

                  {detail.review_status && detail.review_status !== 'none' && (
                    <div className="p-3 bg-[#F8F9FB] rounded-lg border border-[#E5E9EF] text-[11px] text-[#687385]">
                      Review Decision: <strong className="text-[#202631] capitalize">{detail.review_status}</strong>
                    </div>
                  )}
                </div>
              )}
            </div>

            <div className="pt-4 border-t border-[#E5E9EF] text-right">
              <button
                onClick={() => setSelectedId(null)}
                className="px-4 py-2 rounded-lg bg-[#F3F5F7] hover:bg-[#E5E9EF] text-[#202631] text-xs font-medium cursor-pointer"
              >
                Close Drawer
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
