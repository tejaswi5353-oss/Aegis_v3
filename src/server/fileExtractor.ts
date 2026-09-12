import path from 'path';

export interface ExtractedFile {
  text: string;
  metadata: {
    type: string;
    size_kb: number;
    char_count: number;
    truncated: boolean;
    row_count?: number;
    page_count?: number;
  };
}

export function extractFileText(buffer: Buffer, filename: string): ExtractedFile {
  const ext = path.extname(filename).toLowerCase();
  let text = '';
  let rowCount: number | undefined = undefined;
  let pageCount: number | undefined = undefined;

  switch (ext) {
    case '.json': {
      try {
        const raw = buffer.toString('utf-8');
        const parsed = JSON.parse(raw);
        text = JSON.stringify(parsed, null, 2);
      } catch {
        text = buffer.toString('utf-8');
      }
      break;
    }
    case '.csv': {
      const raw = buffer.toString('utf-8');
      const lines = raw.split(/\r?\n/).filter((l) => l.trim().length > 0);
      rowCount = lines.length;
      if (lines.length > 1) {
        const headers = lines[0].split(',');
        text = lines
          .slice(1)
          .map((line) => {
            const cols = line.split(',');
            return cols.map((col, idx) => `${headers[idx]?.trim() || `col${idx}`}: ${col.trim()}`).join(', ');
          })
          .join('\n');
      } else {
        text = raw;
      }
      break;
    }
    case '.pdf': {
      // Extract printable text strings from PDF stream
      const raw = buffer.toString('latin1');
      // Look for text streams / TJ operators or ASCII strings
      const textMatches = raw.match(/\(([^()]{2,})\)\s*T[jJ]|\[([^\]]+)\]\s*TJ/g);
      if (textMatches && textMatches.length > 0) {
        text = textMatches
          .map((m) => m.replace(/[\(\)\[\]]/g, ' ').replace(/\\[nrtbf]/g, ' '))
          .join(' ')
          .replace(/\s+/g, ' ')
          .trim();
      } else {
        // Fallback: extract legible printable ASCII/UTF8 runs
        const runs: string[] = raw.match(/[\x20-\x7E\s]{4,}/g) || [];
        text = runs
          .filter((s: string) => !s.startsWith('%PDF') && !s.includes('/Root') && !s.includes('/Font'))
          .join('\n');
      }
      const pagesMatch = raw.match(/\/Type\s*\/Page\b/g);
      if (pagesMatch) pageCount = pagesMatch.length;
      break;
    }
    case '.docx':
    case '.xlsx': {
      // Office OpenXML formats are zip files containing xml parts
      const raw = buffer.toString('latin1');
      // Extract textual nodes <w:t>...</w:t> or <t>...</t>
      const xmlTextMatches = raw.match(/<(?:\w+:)?t[^>]*>([^<]+)<\/(?:\w+:)?t>/g);
      if (xmlTextMatches && xmlTextMatches.length > 0) {
        text = xmlTextMatches
          .map((tag) => tag.replace(/<[^>]+>/g, ''))
          .join(' ')
          .replace(/\s+/g, ' ')
          .trim();
      } else {
        // Fallback to printable text runs
        const runs = raw.match(/[\x20-\x7E\s]{4,}/g) || [];
        text = runs.join(' ');
      }
      break;
    }
    default: {
      // .txt, .log, .md or other plain text
      text = buffer.toString('utf-8');
      break;
    }
  }

  const truncated = text.length > 8000;
  const finalText = text.slice(0, 8000);

  return {
    text: finalText,
    metadata: {
      type: ext.replace('.', '').toUpperCase(),
      size_kb: Math.round((buffer.length / 1024) * 100) / 100,
      char_count: finalText.length,
      truncated,
      ...(rowCount !== undefined ? { row_count: rowCount } : {}),
      ...(pageCount !== undefined ? { page_count: pageCount } : {}),
    },
  };
}
