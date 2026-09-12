import React, { useState, useRef } from 'react';
import { Upload, X, AlertTriangle, FileText, Loader2, Sparkles, ChevronDown, ChevronUp } from 'lucide-react';
import type { ScanResult } from '../data/scannerEngine';
import { GeminiAuditPanel } from './GeminiAuditPanel';

export interface FileScanResult {
  file_name: string;
  file_metadata: { type?: string; size_kb?: number; char_count?: number; page_count?: number; row_count?: number; truncated?: boolean };
  extracted_preview: string;
  scan_result?: ScanResult | null;
  error?: string | null;
}

const ALLOWED_EXTS = ['.pdf', '.csv', '.json', '.docx', '.xlsx', '.txt', '.log', '.md'];

export const getFileIcon = (fileName: string) => {
  const ext = '.' + fileName.split('.').pop()?.toLowerCase();
  const map: Record<string, string> = { '.pdf': '📕', '.csv': '📊', '.json': '🔷', '.docx': '📘', '.xlsx': '📗' };
  return map[ext] || '📄';
};

interface FileIntelPanelProps {
  onScanComplete?: (results: FileScanResult[]) => void;
  thoroughAiScan?: boolean;
}

export const FileIntelPanel: React.FC<FileIntelPanelProps> = ({ onScanComplete, thoroughAiScan = true }) => {
  const [files, setFiles] = useState<File[]>([]);
  const [scanning, setScanning] = useState<boolean>(false);
  const [results, setResults] = useState<FileScanResult[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [expandedFileAudit, setExpandedFileAudit] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleFiles = (incoming: FileList | File[]) => {
    setError(null);
    const valid: File[] = [];
    for (const f of Array.from(incoming)) {
      const ext = '.' + f.name.split('.').pop()?.toLowerCase();
      if (!ALLOWED_EXTS.includes(ext)) { setError(`Unsupported file type: ${ext}`); return; }
      if (f.size > 5 * 1024 * 1024) { setError(`${f.name} exceeds the 5 MB per-file limit`); return; }
      valid.push(f);
    }
    setFiles(prev => [...prev, ...valid].slice(0, 5));
  };

  const handleScan = async () => {
    if (!files.length || scanning) return;
    setScanning(true);
    setError(null);
    try {
      const formData = new FormData();
      files.forEach(f => formData.append('files', f));
      formData.append('session_id', `intel-${Date.now()}`);
      formData.append('thorough_ai_scan', String(thoroughAiScan));

      const res = await fetch('/api/scan-files', { method: 'POST', body: formData });
      if (!res.ok) {
        const d = await res.json().catch(() => ({}));
        throw new Error(d.error || d.detail || `Scan failed: ${res.status}`);
      }
      const data: FileScanResult[] = await res.json();
      setResults(data);
      onScanComplete?.(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'File scan failed');
    } finally {
      setScanning(false);
    }
  };

  return (
    <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 shadow-xl flex flex-col gap-4 text-slate-200">
      <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
        <span className="text-xs font-semibold uppercase tracking-wider text-slate-300 flex items-center gap-2">
          <FileText className="w-4 h-4 text-blue-400" /> Multi-Format File Intelligence (7 Types)
        </span>
        <span className="text-[11px] font-mono text-slate-500">PDF • CSV • JSON • DOCX • XLSX • TXT • LOG • MD</span>
      </div>

      <div
        onDragOver={e => e.preventDefault()}
        onDrop={e => { e.preventDefault(); if (e.dataTransfer.files) handleFiles(e.dataTransfer.files); }}
        onClick={() => fileInputRef.current?.click()}
        className="border-2 border-dashed border-slate-700/80 hover:border-blue-500/60 bg-slate-950/40 rounded-lg p-6 flex flex-col items-center justify-center gap-2 cursor-pointer transition-colors"
      >
        <Upload className="w-6 h-6 text-blue-400" />
        <p className="text-xs text-slate-300 font-medium">Drag & drop data files here or <span className="text-blue-400 underline">browse</span></p>
        <p className="text-[11px] text-slate-500">Max 5 files • Up to 5 MB per file</p>
        <input ref={fileInputRef} type="file" multiple accept={ALLOWED_EXTS.join(',')} className="hidden" onChange={e => e.target.files && handleFiles(e.target.files)} />
      </div>

      {error && (
        <div className="p-3 bg-red-950/60 border border-red-800 rounded-lg text-red-300 text-xs font-mono flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" /><span>{error}</span>
        </div>
      )}

      {files.length > 0 && (
        <div className="flex flex-col gap-2">
          <span className="text-xs font-mono text-slate-400">Queue ({files.length}/5 files):</span>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
            {files.map((f, i) => (
              <div key={`${f.name}-${i}`} className="flex items-center justify-between p-2.5 bg-slate-950/80 border border-slate-800 rounded-lg text-xs font-mono">
                <span className="truncate flex items-center gap-2"><span>{getFileIcon(f.name)}</span><span className="text-slate-200 truncate">{f.name}</span><span className="text-slate-500">({(f.size / 1024).toFixed(1)} KB)</span></span>
                <button type="button" onClick={(e) => { e.stopPropagation(); setFiles(prev => prev.filter((_, idx) => idx !== i)); }} className="text-slate-500 hover:text-red-400 p-1"><X className="w-3.5 h-3.5" /></button>
              </div>
            ))}
          </div>
          <button type="button" onClick={handleScan} disabled={scanning} className="mt-2 h-10 bg-blue-600 hover:bg-blue-700 active:bg-blue-800 disabled:opacity-50 text-white font-bold rounded-lg shadow-lg shadow-blue-600/20 flex items-center justify-center gap-2 text-xs uppercase tracking-wider transition-all cursor-pointer">
            {scanning ? <><Loader2 className="w-4 h-4 animate-spin" /> Deep Scanning {files.length} Files with Gemini...</> : `Scan ${files.length} File${files.length > 1 ? 's' : ''} with Gemini`}
          </button>
        </div>
      )}

      {results.length > 0 && (
        <div className="flex flex-col gap-3 pt-2">
          <span className="text-xs font-mono text-slate-400 uppercase tracking-wider">Extraction & Scan Results:</span>
          <div className="flex flex-col gap-3">
            {results.map((res, i) => {
              const hasDeepAudit = Boolean(res.scan_result?.gemini_deep_analysis);
              const isExpanded = expandedFileAudit === res.file_name;

              return (
                <div key={i} className="p-4 bg-slate-950/90 border border-slate-800 rounded-lg flex flex-col gap-2 shadow-md">
                  <div className="flex items-center justify-between flex-wrap gap-2">
                    <div className="flex items-center gap-2 text-sm font-semibold">
                      <span>{getFileIcon(res.file_name)}</span>
                      <span className="text-white">{res.file_name}</span>
                      {hasDeepAudit && (
                        <span className="flex items-center gap-1 text-[10px] font-mono font-semibold px-2 py-0.5 rounded bg-blue-500/10 text-blue-300 border border-blue-500/30">
                          <Sparkles className="w-2.5 h-2.5 text-blue-400" />
                          Gemini Audited
                        </span>
                      )}
                    </div>

                    <div className="flex items-center gap-2">
                      {res.error ? (
                        <span className="px-2 py-0.5 rounded border text-[11px] font-bold bg-amber-950/80 text-amber-300 border-amber-800">EXTRACTION FAILED</span>
                      ) : (
                        <span className={`px-2.5 py-0.5 rounded border text-xs font-bold ${res.scan_result?.risk_tier === 'HOSTILE' ? 'bg-red-950/80 text-red-300 border-red-700' : res.scan_result?.risk_tier === 'WARN' ? 'bg-yellow-950/80 text-yellow-300 border-yellow-700' : 'bg-emerald-950/80 text-emerald-300 border-emerald-700'}`}>
                          {res.scan_result?.risk_tier || 'SAFE'} [{res.scan_result?.risk_score ?? 0}]
                        </span>
                      )}

                      {hasDeepAudit && (
                        <button
                          type="button"
                          onClick={() => setExpandedFileAudit(isExpanded ? null : res.file_name)}
                          className="px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[11px] font-mono flex items-center gap-1 border border-slate-700 transition-colors"
                        >
                          {isExpanded ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
                          <span>AI Report</span>
                        </button>
                      )}
                    </div>
                  </div>

                  {res.error ? (
                    <div className="p-2.5 bg-amber-950/40 border border-amber-800/80 rounded text-amber-300 text-xs font-mono">{res.error}</div>
                  ) : (
                    <>
                      <div className="p-2.5 bg-slate-800/90 text-slate-300 font-mono text-xs rounded overflow-hidden whitespace-pre-wrap break-all max-h-24 overflow-y-auto border border-slate-700/50">
                        {res.extracted_preview.slice(0, 250) || '<No text extracted>'}
                      </div>
                      {res.scan_result?.flagged_keyphrases && res.scan_result.flagged_keyphrases.length > 0 && (
                        <div className="flex flex-wrap gap-1.5 mt-1">
                          {res.scan_result.flagged_keyphrases.map((kp, kIdx) => (
                            <span key={kIdx} className="bg-red-500/20 text-red-300 border border-red-500/40 text-[10px] px-2 py-0.5 rounded-full font-mono">{kp}</span>
                          ))}
                        </div>
                      )}

                      {/* Embedded Gemini Deep Audit if expanded */}
                      {isExpanded && res.scan_result?.gemini_deep_analysis && (
                        <div className="mt-2">
                          <GeminiAuditPanel analysis={res.scan_result.gemini_deep_analysis} targetName={res.file_name} />
                        </div>
                      )}
                    </>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
};
