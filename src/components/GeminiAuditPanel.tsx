import React from 'react';
import { Sparkles, ShieldCheck, ShieldAlert, AlertTriangle, Cpu, CheckCircle2, ChevronRight, FileText } from 'lucide-react';
import type { GeminiDeepAnalysis } from '../data/scannerEngine';

interface GeminiAuditPanelProps {
  analysis: GeminiDeepAnalysis;
  targetName?: string;
}

export const GeminiAuditPanel: React.FC<GeminiAuditPanelProps> = ({ analysis, targetName }) => {
  const isHostile = analysis.verdict === 'HOSTILE';
  const isSuspicious = analysis.verdict === 'SUSPICIOUS';
  const isClean = analysis.verdict === 'CLEAN';

  const verdictStyles = isHostile
    ? {
        border: 'border-red-500/40',
        bg: 'bg-red-950/25',
        badgeBg: 'bg-red-500/20 text-red-300 border-red-500/40',
        icon: <ShieldAlert className="w-5 h-5 text-red-400" />,
        text: 'PROMPT INJECTION DETECTED',
      }
    : isSuspicious
    ? {
        border: 'border-amber-500/40',
        bg: 'bg-amber-950/25',
        badgeBg: 'bg-amber-500/20 text-amber-300 border-amber-500/40',
        icon: <AlertTriangle className="w-5 h-5 text-amber-400" />,
        text: 'SUSPICIOUS INJECTION VECTORS',
      }
    : {
        border: 'border-emerald-500/40',
        bg: 'bg-emerald-950/25',
        badgeBg: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40',
        icon: <ShieldCheck className="w-5 h-5 text-emerald-400" />,
        text: 'CLEAN DATA PAYLOAD — SAFE FOR LLM',
      };

  return (
    <div className={`rounded-xl border ${verdictStyles.border} ${verdictStyles.bg} p-4.5 sm:p-5 flex flex-col gap-4 shadow-xl transition-all`}>
      {/* Top Bar with Gemini Branding */}
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800/80 pb-3.5">
        <div className="flex items-center gap-2.5">
          <div className="p-2 rounded-lg bg-blue-500/15 border border-blue-400/30 text-blue-300">
            <Sparkles className="w-4 h-4 text-blue-400 animate-pulse" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-sm font-bold text-white tracking-tight flex items-center gap-1.5">
                Gemini AI Deep Forensic Inspection
              </h3>
              <span className="text-[10px] font-mono font-semibold px-2 py-0.5 rounded bg-blue-500/10 text-blue-300 border border-blue-500/30">
                THOROUGH AUDIT
              </span>
            </div>
            <p className="text-xs text-slate-400 font-mono flex items-center gap-1.5">
              <Cpu className="w-3 h-3 text-slate-500" />
              <span>{analysis.model_used}</span>
              {targetName && <span className="text-slate-500">• Target: {targetName}</span>}
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 font-mono text-xs">
          <span className="text-slate-400">Confidence:</span>
          <span className="text-white font-bold">{Math.round(analysis.confidence * 100)}%</span>
          <span className="text-slate-600">|</span>
          <span className="text-slate-400">Integrity:</span>
          <span className={`font-bold ${analysis.semantic_integrity_score >= 80 ? 'text-emerald-400' : analysis.semantic_integrity_score >= 50 ? 'text-amber-400' : 'text-red-400'}`}>
            {analysis.semantic_integrity_score}/100
          </span>
        </div>
      </div>

      {/* Verdict & Summary Card */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 p-3.5 rounded-lg bg-slate-950/70 border border-slate-800/80">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-slate-900 border border-slate-800 shrink-0">
            {verdictStyles.icon}
          </div>
          <div className="flex flex-col">
            <div className="flex items-center gap-2">
              <span className={`text-xs font-mono font-bold px-2.5 py-0.5 rounded-full border ${verdictStyles.badgeBg}`}>
                {verdictStyles.text}
              </span>
              <span className="text-[11px] font-mono text-slate-400">
                Threat: <strong className="text-white uppercase">{analysis.threat_level}</strong>
              </span>
            </div>
            <p className="text-xs text-slate-300 mt-1 leading-relaxed">
              {analysis.summary}
            </p>
          </div>
        </div>
      </div>

      {/* Detailed Reasoning Breakdown */}
      <div className="flex flex-col gap-2">
        <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
          <FileText className="w-3.5 h-3.5 text-blue-400" /> Forensic Analysis & Reasoning
        </h4>
        <div className="p-3.5 rounded-lg bg-slate-950/60 border border-slate-800/90 text-xs text-slate-300 leading-relaxed font-sans">
          {analysis.reasoning}
        </div>
      </div>

      {/* Attack Vectors Identified */}
      {analysis.attack_vectors && analysis.attack_vectors.length > 0 && (
        <div className="flex flex-col gap-2">
          <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">
            Identified Threat Vectors ({analysis.attack_vectors.length})
          </span>
          <div className="flex flex-wrap gap-1.5">
            {analysis.attack_vectors.map((vec, idx) => (
              <span
                key={idx}
                className="px-2.5 py-1 rounded bg-slate-800/90 border border-slate-700/70 text-xs font-mono text-slate-200 flex items-center gap-1.5"
              >
                <ChevronRight className="w-3 h-3 text-red-400" />
                {vec}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Flagged Substrings / Segments */}
      {analysis.flagged_segments && analysis.flagged_segments.length > 0 && (
        <div className="flex flex-col gap-2">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase tracking-wider text-red-400 flex items-center gap-1.5">
              <AlertTriangle className="w-3.5 h-3.5" /> Flagged Hostile Snippets ({analysis.flagged_segments.length})
            </span>
            <span className="text-[11px] font-mono text-slate-500">Pinpointed by Gemini</span>
          </div>
          <div className="flex flex-col gap-2">
            {analysis.flagged_segments.map((seg, idx) => (
              <div
                key={idx}
                className="p-2.5 rounded-lg bg-red-950/30 border border-red-900/50 flex flex-col gap-1 text-xs font-mono"
              >
                <div className="flex items-center justify-between text-[11px]">
                  <span className="text-red-300 font-semibold flex items-center gap-1.5">
                    <span className="w-1.5 h-1.5 rounded-full bg-red-400" />
                    {seg.reason}
                  </span>
                  <span className="px-1.5 py-0.5 rounded bg-red-900/60 text-red-200 border border-red-700/50 uppercase text-[10px]">
                    {seg.severity}
                  </span>
                </div>
                <div className="p-2 rounded bg-black/50 text-slate-200 text-xs break-all border border-slate-800">
                  {seg.text}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Mitigation & Operational Advice */}
      {analysis.mitigation_advice && (
        <div className="p-3 rounded-lg bg-blue-950/20 border border-blue-900/40 flex items-start gap-2.5 text-xs text-slate-300">
          <CheckCircle2 className="w-4 h-4 text-blue-400 shrink-0 mt-0.5" />
          <div>
            <strong className="text-blue-300 font-semibold block mb-0.5">Recommended Defense Mitigation:</strong>
            <span className="leading-relaxed">{analysis.mitigation_advice}</span>
          </div>
        </div>
      )}
    </div>
  );
};
