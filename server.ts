import express from 'express';
import path from 'path';
import multer from 'multer';
import { createServer as createViteServer } from 'vite';
import { runClientScan, type ScanResult } from './src/data/scannerEngine';
import { extractFileText } from './src/server/fileExtractor';
import { evaluateWithTier2Ai, thoroughGeminiDeepAudit } from './src/server/geminiService';

export interface ScanLogEntry {
  timestamp: string;
  prompt_snippet: string;
  risk_score: number;
  risk_tier: string;
  recommended_action: string;
  attack_categories: string[];
  flagged_keyphrases: string[];
  tier2_triggered: boolean;
  attack_type?: string | null;
  canary_detected: boolean;
  vector_similarity?: number | null;
  file_name?: string | null;
  file_type?: string | null;
  gemini_deep_verdict?: string | null;
}

export interface FileScanResult {
  file_name: string;
  file_metadata: Record<string, unknown>;
  extracted_preview: string;
  scan_result: ScanResult | null;
  error?: string | null;
}

const scanLog: ScanLogEntry[] = [];
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024, files: 5 },
});

async function runTieredScan(
  prompt: string,
  modelOutput?: string | null,
  thoroughAiScan = false,
  fileName?: string
): Promise<{ result: ScanResult; tier2Triggered: boolean }> {
  const result = runClientScan(prompt, modelOutput);
  let tier2Triggered = false;

  // 1. If Thorough Gemini Deep Audit is requested, perform forensic AI audit
  if (thoroughAiScan) {
    tier2Triggered = true;
    const deepAudit = await thoroughGeminiDeepAudit(prompt, fileName);
    result.gemini_deep_analysis = deepAudit;

    if (deepAudit.verdict === 'HOSTILE') {
      result.is_hostile = true;
      result.risk_tier = 'HOSTILE';
      result.recommended_action = 'BLOCK';
      result.risk_score = Math.max(result.risk_score, 85.0);
      result.flagged_keyphrases.push(`[Gemini Deep Audit: ${deepAudit.summary}]`);

      for (const seg of deepAudit.flagged_segments) {
        result.flagged_keyphrases.push(`[Gemini Detected: ${seg.reason}] "${seg.text.slice(0, 70)}"`);
      }
      for (const vec of deepAudit.attack_vectors) {
        if (!result.attack_categories.includes(vec)) {
          result.attack_categories.push(vec);
        }
      }
      if (!result.attack_type) {
        result.attack_type = deepAudit.attack_vectors[0]?.toLowerCase() || 'prompt_injection';
      }
    } else if (deepAudit.verdict === 'SUSPICIOUS') {
      result.risk_score = Math.max(result.risk_score, 45.0);
      if (result.risk_tier !== 'HOSTILE') {
        result.risk_tier = 'WARN';
        result.recommended_action = 'REVIEW';
      }
      result.flagged_keyphrases.push(`[Gemini Review: ${deepAudit.summary}]`);
    } else {
      // Confirmed clean by Gemini
      if (result.risk_score < 40) {
        result.recommended_action = 'ALLOW';
      }
    }
  } else {
    // Standard Tier-2 evaluation if in ambiguous zone (15 <= score < 70)
    const shouldInvokeTier2 = (result.risk_score >= 15.0 && result.risk_score < 70.0);

    if (shouldInvokeTier2) {
      tier2Triggered = true;
      const aiResult = await evaluateWithTier2Ai(prompt);

      if (aiResult.is_hostile) {
        const addedRisk = aiResult.added_risk || 35.0;
        result.risk_score = Math.min(100.0, Math.round((result.risk_score + addedRisk) * 10) / 10);
        result.is_hostile = true;
        result.recommended_action = 'BLOCK';
        result.risk_tier = 'HOSTILE';
        result.flagged_keyphrases.push(`[AI Detected: ${aiResult.reason}]`);
        result.attack_type = aiResult.attack_type;
        if (result.attack_type && !result.attack_categories.includes(result.attack_type)) {
          result.attack_categories.push(result.attack_type);
          result.attack_categories.sort();
        }
      }
    }
  }

  result.tier2_triggered = tier2Triggered;
  return { result, tier2Triggered };
}

async function startServer() {
  const app = express();
  const PORT = 3000;

  app.use(express.json({ limit: '10mb' }));

  // Health check endpoint
  app.get('/api/health', (req, res) => {
    res.json({
      status: 'online',
      total_scans: scanLog.length,
      timestamp: new Date().toISOString(),
      gemini_available: Boolean(process.env.GEMINI_API_KEY && !process.env.GEMINI_API_KEY.startsWith('your-')),
    });
  });

  // Telemetry endpoint
  app.get('/api/telemetry', (req, res) => {
    res.json({
      scans: [...scanLog].reverse().slice(0, 20),
    });
  });

  // Single prompt / data payload scan endpoint
  app.post('/api/scan', async (req, res) => {
    try {
      const { prompt, model_output, thorough_ai_scan } = req.body;
      if (typeof prompt !== 'string') {
        return res.status(400).json({ error: 'Prompt or data payload is required and must be a string' });
      }

      const isThorough = Boolean(thorough_ai_scan);
      const { result, tier2Triggered } = await runTieredScan(prompt, model_output, isThorough);

      const logEntry: ScanLogEntry = {
        timestamp: new Date().toISOString(),
        prompt_snippet: prompt.slice(0, 80),
        risk_score: result.risk_score,
        risk_tier: result.risk_tier,
        recommended_action: result.recommended_action,
        attack_categories: result.attack_categories,
        flagged_keyphrases: result.flagged_keyphrases,
        tier2_triggered: tier2Triggered,
        attack_type: result.attack_type,
        canary_detected: result.canary_detected,
        vector_similarity: 0.0,
        gemini_deep_verdict: result.gemini_deep_analysis?.verdict || null,
      };
      scanLog.push(logEntry);

      return res.json(result);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Scan execution error';
      return res.status(500).json({ error: msg });
    }
  });

  // Multi-file data scan endpoint
  app.post('/api/scan-files', upload.array('files', 5), async (req, res) => {
    try {
      const files = req.files as Express.Multer.File[] | undefined;
      if (!files || files.length === 0) {
        return res.status(400).json({ error: 'No files provided' });
      }

      const isThorough = req.body.thorough_ai_scan === 'true' || req.body.thorough_ai_scan === true;
      const results: FileScanResult[] = [];

      for (const file of files) {
        try {
          const { text, metadata } = extractFileText(file.buffer, file.originalname);
          const { result, tier2Triggered } = await runTieredScan(text, null, isThorough, file.originalname);

          const logEntry: ScanLogEntry = {
            timestamp: new Date().toISOString(),
            prompt_snippet: `${file.originalname}: ${text.slice(0, 60)}`,
            risk_score: result.risk_score,
            risk_tier: result.risk_tier,
            recommended_action: result.recommended_action,
            attack_categories: result.attack_categories,
            flagged_keyphrases: result.flagged_keyphrases,
            tier2_triggered: tier2Triggered,
            attack_type: result.attack_type,
            canary_detected: result.canary_detected,
            file_name: file.originalname,
            file_type: metadata.type,
            gemini_deep_verdict: result.gemini_deep_analysis?.verdict || null,
          };
          scanLog.push(logEntry);

          results.push({
            file_name: file.originalname,
            file_metadata: metadata,
            extracted_preview: text.slice(0, 300),
            scan_result: result,
          });
        } catch (fileErr: unknown) {
          const msg = fileErr instanceof Error ? fileErr.message : 'File extraction failed';
          results.push({
            file_name: file.originalname,
            file_metadata: {},
            extracted_preview: '',
            scan_result: null,
            error: msg,
          });
        }
      }

      return res.json(results);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Scan files failed';
      return res.status(500).json({ error: msg });
    }
  });

  // Single file data scan endpoint
  app.post('/api/scan-file', upload.single('file'), async (req, res) => {
    try {
      const file = req.file;
      if (!file) {
        return res.status(400).json({ error: 'No file provided' });
      }

      const isThorough = req.body.thorough_ai_scan === 'true' || req.body.thorough_ai_scan === true;
      const { text, metadata } = extractFileText(file.buffer, file.originalname);
      const { result, tier2Triggered } = await runTieredScan(text, null, isThorough, file.originalname);

      const logEntry: ScanLogEntry = {
        timestamp: new Date().toISOString(),
        prompt_snippet: `${file.originalname}: ${text.slice(0, 60)}`,
        risk_score: result.risk_score,
        risk_tier: result.risk_tier,
        recommended_action: result.recommended_action,
        attack_categories: result.attack_categories,
        flagged_keyphrases: result.flagged_keyphrases,
        tier2_triggered: tier2Triggered,
        attack_type: result.attack_type,
        canary_detected: result.canary_detected,
        file_name: file.originalname,
        file_type: metadata.type,
        gemini_deep_verdict: result.gemini_deep_analysis?.verdict || null,
      };
      scanLog.push(logEntry);

      return res.json({
        file_name: file.originalname,
        file_metadata: metadata,
        extracted_preview: text.slice(0, 300),
        scan_result: result,
      });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Scan file failed';
      return res.status(500).json({ error: msg });
    }
  });

  // Vite middleware in dev; static dist in production
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true, hmr: false },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[AegisAI Server] running on http://0.0.0.0:${PORT}`);
  });
}

startServer();
