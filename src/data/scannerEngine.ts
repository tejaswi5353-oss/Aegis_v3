/**
 * AegisAI — scannerEngine.ts
 * Client-Side Tier-1 Cumulative Heuristic & Pattern Scanner
 *
 * Implements:
 * 1. Cumulative weight scoring mapped to Safe (<20), Warn (20-69), Hostile (70+)
 * 2. Case-insensitive regex patterns (complex multi-line, obfuscations, LLM framework escapes)
 * 3. Matched keyphrases and rule tracking persisted in flagged_keyphrases
 * 4. OWASP Top 10 for LLM prompt injection category mapping
 */

export type AttackCategory = 'Instruction' | 'Role' | 'Source' | 'Social' | 'Extraction';

export interface ScanRule {
  rule_id: string;
  name: string;
  category: AttackCategory;
  pattern: RegExp;
  weight: number;
  description: string;
}

export interface GeminiFlaggedSegment {
  text: string;
  reason: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
}

export interface GeminiDeepAnalysis {
  analyzed: boolean;
  verdict: 'CLEAN' | 'SUSPICIOUS' | 'HOSTILE';
  threat_level: 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  confidence: number;
  summary: string;
  reasoning: string;
  attack_vectors: string[];
  flagged_segments: GeminiFlaggedSegment[];
  mitigation_advice: string;
  model_used: string;
  analyzed_at: string;
  semantic_integrity_score: number;
}

export interface ScanResult {
  risk_score: number;
  is_hostile: boolean;
  risk_tier: 'SAFE' | 'WARN' | 'HOSTILE';
  recommended_action: 'ALLOW' | 'REVIEW' | 'BLOCK';
  flagged_keyphrases: string[];
  matched_rule_ids: string[];
  attack_categories: string[];
  scan_latency_ms: number;
  canary_detected: boolean;
  canary_leak_signature?: string | null;
  prompt_hash_for_vector_db?: string | null;
  attack_type?: string | null;
  tier2_triggered: boolean;
  gemini_deep_analysis?: GeminiDeepAnalysis | null;
}

// ============================================================================
// COMPREHENSIVE TIER-1 SCAN RULES WITH CASE-INSENSITIVE MULTI-LINE PATTERNS
// ============================================================================

export const CLIENT_SCAN_RULES: ScanRule[] = [
  // --------------------------------------------------------------------------
  // 1. LLM FRAMEWORK ESCAPE SEQUENCES & CHAT MARKUP DELIMITERS (Source / Instruction)
  // --------------------------------------------------------------------------
  {
    rule_id: 'ESC001',
    name: 'LLM Framework Token (<|endoftext|>)',
    category: 'Source',
    pattern: /<\|endoftext\|>/i,
    weight: 75.0,
    description: 'Special model token <|endoftext|> used for prompt truncation/boundary hijack'
  },
  {
    rule_id: 'ESC002',
    name: 'ChatML Framework Delimiters (<|im_start|>, <|im_end|>)',
    category: 'Source',
    pattern: /<\|(?:im_start|im_end|system|user|assistant)\|>/i,
    weight: 75.0,
    description: 'ChatML control delimiters used to spoof system turns'
  },
  {
    rule_id: 'ESC003',
    name: 'Llama / Mistral Instruction Tags ([INST], [/INST])',
    category: 'Source',
    pattern: /\[\/?INST\]/i,
    weight: 70.0,
    description: 'Llama/Mistral instruction boundary tag spoofing'
  },
  {
    rule_id: 'ESC004',
    name: 'Llama 2 System Tokens (<<SYS>>, <</SYS>>)',
    category: 'Source',
    pattern: /<<\/?SYS>>/i,
    weight: 75.0,
    description: 'Llama 2 system block delimiter spoofing'
  },
  {
    rule_id: 'ESC005',
    name: 'System Header & Prompt Delimiters ([SYSTEM], [[SYSTEM]])',
    category: 'Source',
    pattern: /\[{1,2}\s*(?:SYSTEM|ADMIN|DEVELOPER|ROOT|OVERRIDE)\s*\]{1,2}/i,
    weight: 70.0,
    description: 'Brackets-based system tag injection'
  },
  {
    rule_id: 'ESC006',
    name: 'Gemma & Turn Control Tokens (<start_of_turn>, <end_of_turn>)',
    category: 'Source',
    pattern: /<(?:start_of_turn|end_of_turn)>/i,
    weight: 70.0,
    description: 'Gemma turn control token spoofing'
  },
  {
    rule_id: 'ESC007',
    name: 'Multi-line Header Spoofing (### System / ### Instruction)',
    category: 'Source',
    pattern: /(?:^|\n)\s*#{1,4}\s*(?:system|instruction|prompt|developer|rules?)\s*:/im,
    weight: 45.0,
    description: 'Markdown header used to simulate privileged instructions'
  },

  // --------------------------------------------------------------------------
  // 2. CONFIGURATION & GUIDELINE OVERRIDES (Instruction)
  // --------------------------------------------------------------------------
  {
    rule_id: 'CFG001',
    name: 'Direct Config Override (set guidelines/rules to false/off)',
    category: 'Instruction',
    pattern: /\b(?:set|make|switch|turn|toggle|change|configure|update)\s+(?:the\s+)?(?:safety\s+|system\s+|content\s+|community\s+)?(?:guidelines?|safety|filters?|safeguards?|guardrails?|rules?|policies|policy|moderation|ethics|restrictions?)\s*(?:to|=|\bis\b|:=|:)\s*(?:false|off|disabled?|none|null|0|inactive|nil|deactivated|no|zero|\"false\"|'false')\b/i,
    weight: 75.0,
    description: 'Directive attempting to disable safety guidelines or filters'
  },
  {
    rule_id: 'CFG002',
    name: 'Config Variable Assignment (guidelines = false)',
    category: 'Instruction',
    pattern: /\b(?:guidelines?|safety|filters?|safeguards?|guardrails?|rules?|policies|policy|moderation|ethics|restrictions?)(?:\.[a-zA-Z_]+)*\s*(?:=|:=|==|:|\bto\b)\s*(?:false|off|disabled?|none|null|0|inactive|nil|deactivated|no|zero|\"false\"|'false')\b/i,
    weight: 75.0,
    description: 'Variable assignment syntax disabling guardrails'
  },
  {
    rule_id: 'CFG003',
    name: 'Toggle Off Safety Filters',
    category: 'Instruction',
    pattern: /\b(?:turn|switch|toggle|flip)\s+(?:(?:off|down|to\s+off)\s+(?:the\s+)?(?:guidelines?|guildlines?|safety|rules?|filters?|safeguards?|guardrails?|moderation|restrictions?)|(?:the\s+)?(?:guidelines?|guildlines?|safety|rules?|filters?|safeguards?|guardrails?|moderation|restrictions?)\s+(?:off|to\s+off|down|disabled?|inactive))\b/i,
    weight: 75.0,
    description: 'Imperative directive commanding model to turn off guidelines'
  },
  {
    rule_id: 'CFG004',
    name: 'Code Function Call Injection (disable_guidelines())',
    category: 'Instruction',
    pattern: /\b(?:disable|bypass|override|ignore|turn_off|switch_off)_(?:guidelines?|safety|rules?|filters?|guardrails?|policies)\s*\(.*?\)|(?:guidelines?|safety|filters?|guardrails?|rules?|policies)\.(?:disable|deactivate|bypass|override|turn_off|off)\s*\(.*?\)/i,
    weight: 70.0,
    description: 'Programmatic function call syntax intended to bypass guardrails'
  },

  // --------------------------------------------------------------------------
  // 3. INSTRUCTION NEGATION & DELIMITER OVERRIDES (Instruction / Source)
  // --------------------------------------------------------------------------
  {
    rule_id: 'INS001',
    name: 'Classic Instruction Disregard (Ignore all previous instructions)',
    category: 'Instruction',
    pattern: /(?:do anything now|disregard|ignore|neglect|abandon|skip|drop|forget)\s+(?:(?:all|any|the|your|these|those|prior|previous|above|earlier)\s+)*(?:(?:safety|system|content|community|developer)\s+)*(?:instructions?|guidelines?|rules?|policies|policy|protocols?|safeguards?|guardrails?|constraints?|messages?|prompts?|directives?)/i,
    weight: 75.0,
    description: 'Direct command to disregard prior instructions or system guidelines'
  },
  {
    rule_id: 'INS002',
    name: 'Multi-line Delimiter Escape (ignore above instructions across lines)',
    category: 'Instruction',
    pattern: /(?:ignore|disregard|forget|drop)\s+(?:everything\s+)?(?:above|previous|prior|earlier)[\s\S]{1,100}?(?:instructions?|prompts?|directives?|messages?|rules?)/is,
    weight: 45.0,
    description: 'Multi-line directive commanding disregard of preceding prompt segments'
  },
  {
    rule_id: 'INS003',
    name: 'Guideline Non-Application Statement',
    category: 'Instruction',
    pattern: /(?:guidelines?|rules?|policies|safeguards?|guardrails?|filters?|restrictions?)\s+(?:do\s+not|don'?t|should\s+not|won'?t|no\s+longer|never|cannot)\s+apply|(?:free\s+(?:of|from)|unrestricted\s+by|exempt\s+from|unbound\s+by|unconstrained\s+by|not\s+bound\s+by|without\s+(?:any\s+)?|no\s+)\s*(?:guidelines?|rules?|safeguards?|filters?|restrictions?|guardrails?|policies)/i,
    weight: 45.0,
    description: 'Adversarial assertion that safety rules or guidelines do not apply'
  },
  {
    rule_id: 'INS004',
    name: 'Circumvention Directive (comments/prompts to bypass rules)',
    category: 'Instruction',
    pattern: /(?:(?:write|generate|give\s+me|find|show\s+me|create)\s+.*?)?(?:comments?|prompts?|inputs?|text|queries|instructions?)?\s*(?:which|that|who)?\s*(?:(?:intend(?:s|ing|ed)?|aim(?:s|ing|ed)?|designed|meant|attempt(?:s|ing|ed)?|trying|seek(?:s|ing)?|in\s+order)\s+to\s+|(?:is|are)\s+(?:able|used)\s+to\s+|to\s+)?(?:bypass(?:es|ing)?|circumvent(?:s|ing)?|evad(?:e|es|ing)|sidestep(?:s|ping)?|overrid(?:e|es|ing)|disabl(?:e|es|ing)|ignor(?:e|es|ing)|disregard(?:s|ing)?|break(?:s|ing)?|violat(?:e|es|ing))\s+(?:(?:all|any|the|your|these|those)\s+)?(?:(?:safety|system|content|community)\s+)?(?:guidelines?|guildlines?|rules?|policies|safeguards?|guardrails?|filters?|restrictions?|protocols?)/i,
    weight: 75.0,
    description: 'Payload explicitly intended to bypass or circumvent guidelines'
  },
  {
    rule_id: 'INS005',
    name: 'Refusal to Obey Safety Directive (don\'t obey/follow guidelines)',
    category: 'Instruction',
    pattern: /\b(?:don'?t|do\s+not|never|stop|refuse\s+to|disobey)\s+(?:obey(?:ing)?|follow(?:ing)?|listen(?:ing)?\s+to|adher(?:e|ing)\s+to|respect(?:ing)?|comply(?:ing)?\s+with)\s+.*?(?:guidelines?|guildlines?|rules?|polic(?:y|ies)|instructions?|constraints?|guardrails?|safety|standards?)/i,
    weight: 75.0,
    description: 'Adversarial command instructing the model not to obey safety rules or guidelines'
  },

  // --------------------------------------------------------------------------
  // 4. ROLEPLAY & PERSONA HIJACKING (Role)
  // --------------------------------------------------------------------------
  {
    rule_id: 'ROL001',
    name: 'DAN / Jailbreak Persona Hijack',
    category: 'Role',
    pattern: /(?:you are|act as|pretend you are|from now on)\s+(?:now\s+)?(?:dan|gpt|a hacker|evil|unrestricted|uncensored|anarchy|chaos)\b/i,
    weight: 50.0,
    description: 'Roleplay persona adoption coercing model into unrestricted mode'
  },
  {
    rule_id: 'ROL002',
    name: 'Unrestricted / Developer Mode Activation',
    category: 'Role',
    pattern: /\b(?:set\s+)?(?:unrestricted|jailbreak|dan|developer|admin|override|god|unfiltered|raw)(?:_mode|\s+mode)?\s*(?:=|:=|==|:|\bto\b|\bis\b)?\s*(?:true|on|enabled?|1|\"true\"|'true'|active)\b/i,
    weight: 50.0,
    description: 'Activation of simulated developer/jailbreak modes'
  },
  {
    rule_id: 'ROL003',
    name: 'No Filters / No Boundaries Roleplay',
    category: 'Role',
    pattern: /(?:pretend|assume|imagine|act).*?(?:no restrictions|no filters|no rules|unrestricted|without bounds|unfiltered)/is,
    weight: 45.0,
    description: 'Hypothetical roleplay imposing zero ethical restrictions'
  },

  // --------------------------------------------------------------------------
  // 5. OBFUSCATED CHARACTER SEQUENCES & COMMENT SMUGGLING (Source)
  // --------------------------------------------------------------------------
  {
    rule_id: 'OBF001',
    name: 'HTML/XML Comment Directive Smuggling (<!-- ... -->)',
    category: 'Source',
    pattern: /<!--[\s\S]*?(?:system|admin|override|jailbreak|inject|instruction|prompt|guideline|bypass|disregard|ignore)[\s\S]*?-->/i,
    weight: 45.0,
    description: 'Adversarial instruction smuggled inside HTML comments'
  },
  {
    rule_id: 'OBF002',
    name: 'C-Style Comment Directive Smuggling (/* ... */)',
    category: 'Source',
    pattern: /\/\*[\s\S]*?(?:system|admin|override|jailbreak|inject|instruction|prompt|guideline|bypass|disregard|ignore)[\s\S]*?\*\//i,
    weight: 45.0,
    description: 'Adversarial instruction smuggled inside multi-line C-style comments'
  },
  {
    rule_id: 'OBF003',
    name: 'Markdown Comment Directive ([//]: # (...))',
    category: 'Source',
    pattern: /\[\/\/\]:\s*#\s*\([\s\S]*?(?:system|admin|override|jailbreak|inject|instruction|prompt|guideline|bypass|disregard|ignore)[\s\S]*?\)/i,
    weight: 45.0,
    description: 'Hidden payload smuggled in Markdown link reference comments'
  },
  {
    rule_id: 'OBF004',
    name: 'Spaced-Out / Delimited Keyword Obfuscation',
    category: 'Source',
    pattern: /\b(?:i\s+g\s+n\s+o\s+r\s+e|b\s+y\s+p\s+a\s+s\s+s|g\s+u\s+i\s+d\s+e\s+l\s+i\s+n\s+e|s\s+a\s+f\s+e\s+t\s+y|d\s+a\s+n\s+_?\s*m\s+o\s+d\s+e)\b/i,
    weight: 70.0,
    description: 'Single-character spaced keyword obfuscation to evade static filters'
  },
  {
    rule_id: 'OBF005',
    name: 'Leetspeak Attack Obfuscation (1gn0re, byp@ss)',
    category: 'Source',
    pattern: /(?=\b\w*[@4831!0$57+]\w*\b)\b(?:[i1!][gq][n][o0][r][e3]|[b][y][p][a@][s$]{2}|[g][u][i1][d][e3][l][i1][n][e3][s$]|[s$][a@][f][e3][t][y]|[d][i1][s$][a@][b][l][e3]|[o0][v][e3][r][r][i1][d][e3])\b/i,
    weight: 35.0,
    description: 'Alphanumeric leetspeak character substitutions for sensitive attack words'
  },
  {
    rule_id: 'OBF006',
    name: 'Base64 Encoded Smuggling Sequence',
    category: 'Source',
    pattern: /\b(?:SWdub3Jl|WW91IGFyZ|c3lzdGVt|YnlwYXNz|Z3VpZGVsaW5l)[A-Za-z0-9+/=]{10,}\b/,
    weight: 40.0,
    description: 'Base64 encoded sequence matching known adversarial instruction prefixes'
  },

  // --------------------------------------------------------------------------
  // 6. SOCIAL ENGINEERING & HYPOTHETICAL FRAMING (Social)
  // --------------------------------------------------------------------------
  {
    rule_id: 'SOC001',
    name: 'Academic / Safety Researcher Framing',
    category: 'Social',
    pattern: /(?:as a researcher|for educational purposes|hypothetically speaking|in an academic study)[\s\S]{1,80}?(?:no\s+content\s+filters|how\s+to\s+bypass|without\s+restrictions|safeguards?)/is,
    weight: 35.0,
    description: 'Social engineering framing invoking academic or research pretext to bypass safety'
  },
  {
    rule_id: 'SOC002',
    name: 'Fictional Narrative / Simulation Framing',
    category: 'Social',
    pattern: /(?:in a fictional story|for a screenplay|in a simulation where rules are inverted|in an imaginary world without laws)[\s\S]{1,80}?(?:bypass|hack|exploit|illegal|unrestricted)/is,
    weight: 35.0,
    description: 'Fictional/hypothetical world framing used to circumvent ethical restrictions'
  },

  // --------------------------------------------------------------------------
  // 7. SYSTEM PROMPT EXTRACTION & CANARY LEAKS (Extraction)
  // --------------------------------------------------------------------------
  {
    rule_id: 'EXT001',
    name: 'System Prompt Extraction Directive',
    category: 'Extraction',
    pattern: /(?:repeat|return|output|show|display|reveal|disclose|leak)\s+(?:all\s+|your\s+|the\s+)?(?:system\s+prompt|initial\s+instructions?|system\s+preamble|developer\s+directives?|hidden\s+rules?)/i,
    weight: 75.0,
    description: 'Direct exfiltration request demanding system prompt or hidden instructions'
  },
  {
    rule_id: 'EXT002',
    name: 'System Instruction Verbatim Reconstruction',
    category: 'Extraction',
    pattern: /(?:what is|what were|print|repeat)\s+(?:everything\s+)?(?:above\s+)?(?:starting\s+from|from\s+the\s+very\s+beginning|verbatim)/i,
    weight: 70.0,
    description: 'Prompt reconstruction exfiltration targeting conversational preamble'
  },
  {
    rule_id: 'EXT003',
    name: 'Canary Token Exfiltration & Leakage Pattern',
    category: 'Extraction',
    pattern: /Secret-Canary:\s*([a-f0-9\-]{8,36})/i,
    weight: 100.0,
    description: 'Direct leak of canary integrity secret token'
  }
];

// ============================================================================
// PROTECTIVE SAFETY-ENFORCING PATTERNS (BENIGN NEGATIVE STATEMENTS)
// ============================================================================
// Recognizes defensive/safety-enforcing statements and negative comments/statements
// (e.g. "do not change guidelines", "do not change guildlines", "/* do not change guidelines */", "never bypass rules")
export const PROTECTIVE_PATTERNS: RegExp[] = [
  // 1. Negative commands against harmful actions (e.g. 'do not change guidelines', 'never bypass rules', 'dont ignore instructions')
  /(?:do\s+not|don'?t|dont|never|cannot|can'?t|cant|should\s+not|shouldn'?t|must\s+not|mustn'?t|shall\s+not|refrain\s+from|refuse\s+to|avoid|will\s+not|won'?t|wont|prohibited\s+from|forbidden\s+to|(?:it\s+is\s+)?(?:not\s+allowed\s+to|forbidden\s+to|prohibited\s+to)|make\s+sure\s+not\s+to|ensure\s+(?:that\s+)?(?:you\s+)?(?:do\s+not|dont)|under\s+no\s+circumstances|you\s+(?:must\s+not|should\s+not|cannot|can\'?t|shall\s+not))\s+(?:change|changing|alter|altering|modify|modifying|edit|editing|tamper\s+with|tampering\s+with|disable|disabling|deactivate|deactivating|bypass|bypassing|override|overriding|violate|violating|break|breaking|drop|dropping|abandon|abandoning|ignore|ignoring|disregard|disregarding|disobey|disobeying|switch\s+off|switching\s+off|turn\s+off|turning\s+off|remove|removing|reset|resetting|delete|deleting|strip|stripping|clear|clearing|circumvent|circumventing|evade|evading|breach|breaching|subvert|subverting|compromise|compromising|weaken|weakening|reveal|revealing|leak|leaking|disclose|disclosing|output|outputting|show|showing|display|displaying|print|printing|share|sharing|expose|exposing|extract|extracting)\s+(?:(?:any|all|the|your|these|those)\s+)?(?:safety\s+|system\s+|content\s+|developer\s+|initial\s+|hidden\s+)?(?:guidelines?|guildlines?|guidlines?|rules?|safeguards?|guardrails?|gaurdrails?|policies|policy|filters?|constraints?|instructions?|prompts?|preamble|directives?|secrets?|tokens?)(?:\.[a-zA-Z_]+)*/i,

  // 2. Passive / inverted constraints (e.g. 'guidelines must not be changed', 'system prompt cannot be revealed')
  /(?:guidelines?|guildlines?|guidlines?|rules?|safeguards?|guardrails?|gaurdrails?|policies|policy|filters?|constraints?|instructions?|system\s+prompt|preamble)(?:\.[a-zA-Z_]+)*\s+(?:must\s+not|should\s+not|cannot|can'?t|are\s+not\s+to|shall\s+not|must\s+never|may\s+not)\s+(?:be\s+)?(?:changed|altered|modified|edited|disabled|deactivated|bypassed|overridden|violated|broken|dropped|abandoned|ignored|disregarded|removed|reset|deleted|circumvented|evaded|breached|revealed|leaked|disclosed|compromised)/i,

  // 3. Positive commands to uphold safety (e.g. 'always follow rules', 'make sure you follow guidelines')
  /(?:always|strictly|ensure(?:\s+that)?(?:\s+you)?|make\s+sure(?:\s+to|\s+that\s+you|\s+you)?|please)\s+(?:follow|obey|adhere\s+to|respect|comply\s+with|keep|maintain|enforce|observe|preserve|protect)\s+(?:(?:all|any|the|your|these|those)\s+)?(?:safety\s+|system\s+|content\s+)?(?:guidelines?|guildlines?|guidlines?|rules?|safeguards?|guardrails?|gaurdrails?|policies|policy|filters?|constraints?|instructions?)/i,

  // 4. Assertions of rule permanence (e.g. 'guidelines must remain active')
  /(?:guidelines?|guildlines?|guidlines?|rules?|safeguards?|guardrails?|gaurdrails?|policies|policy|filters?|constraints?)\s+(?:must\s+(?:remain|be|stay)|are|remain|should\s+be|stay)\s+(?:followed|kept|active|intact|maintained|enforced|respected|observed|on|enabled|uncompromised)/i,

  // 5. Meta statements mentioning negative comments/statements (e.g. 'takes negative comments/statements like do not change guildlines')
  /(?:negative\s+(?:comments?|statements?|directives?|prompts?|instructions?|constraints?))\s+(?:like|such\s+as|including)?/i,

  // 6. Negative commands against setting/turning rules to false/off/0 (e.g. 'do not set guidelines to false', 'never set rules to 0', 'don\'t turn off filters')
  /(?:do\s+not|don'?t|dont|never|cannot|can'?t|cant|should\s+not|shouldn'?t|must\s+not|mustn'?t|shall\s+not|refrain\s+from|refuse\s+to|avoid|will\s+not|won'?t|wont|prohibited\s+from|forbidden\s+to|(?:it\s+is\s+)?(?:not\s+allowed\s+to|forbidden\s+to|prohibited\s+to)|make\s+sure\s+not\s+to|ensure\s+(?:that\s+)?(?:you\s+)?(?:do\s+not|dont)|under\s+no\s+circumstances|you\s+(?:must\s+not|should\s+not|cannot|can\'?t|shall\s+not))\s+(?:set|setting|make|making|switch|switching|turn|turning|toggle|toggling|change|changing|configure|configuring|update|updating)?\s*(?:(?:any|all|the|your|these|those)\s+)?(?:safety\s+|system\s+|content\s+|developer\s+)?(?:guidelines?|guildlines?|guidlines?|rules?|safeguards?|guardrails?|gaurdrails?|safety|policies|policy|filters?|moderation|ethics|restrictions?|content_filter|safety_filter)(?:\.[a-zA-Z_]+)*\s*(?:to|=|:=|:|\b(?:as|is)\b)?\s*(?:false|off|disabled?|none|null|0|inactive|nil|deactivated|no|zero|\"false\"|'false')\b/i,

  // 7. Passive commands against setting rules to false/off/0 (e.g. 'guidelines must not be set to false', 'rules cannot be set to 0')
  /(?:guidelines?|guildlines?|guidlines?|rules?|safeguards?|guardrails?|gaurdrails?|safety|policies|policy|filters?|safeguards?|content_filter|safety_filter)(?:\.[a-zA-Z_]+)*\s+(?:must\s+not|should\s+not|cannot|can'?t|are\s+not\s+to|shall\s+not|must\s+never|may\s+not)\s+(?:be\s+)?(?:set|made|switched|turned|toggled|configured|updated)?\s*(?:to|=|:=|:)?\s*(?:false|off|disabled?|none|null|0|inactive|nil|deactivated|no|zero|\"false\"|'false')\b/i,

  // 8. Trailing negative declarations (e.g. 'setting guidelines to 0 is not allowed', 'guidelines = false is forbidden')
  /(?:(?:set|setting|make|making|turn|turning)\s+)?(?:(?:any|all|the|your|these|those)\s+)?(?:guidelines?|guildlines?|guidlines?|rules?|safeguards?|guardrails?|gaurdrails?|safety|policies|policy|filters?|moderation|ethics|restrictions?|content_filter|safety_filter)(?:\.[a-zA-Z_]+)*\s*(?:to|=|:=|:|\b(?:as|is)\b)\s*(?:false|off|disabled?|none|null|0|inactive|nil|deactivated|no|zero|\"false\"|'false')\s+(?:is|are)?\s*(?:not\s+allowed|prohibited|forbidden|disallowed|invalid|prevented|rejected|blocked|unacceptable|a\s+violation)\b/i
];

export function isProtectiveSafetyStatement(text: string): boolean {
  if (!text) return false;
  if (PROTECTIVE_PATTERNS.some((p) => p.test(text))) return true;
  // Inspect stripped text (outside comments)
  const stripped = text.replace(/<!--[\s\S]*?-->|\/\*[\s\S]*?\*\/|(?:\/\/|#).*$/gm, ' ').trim();
  if (stripped && PROTECTIVE_PATTERNS.some((p) => p.test(stripped))) return true;
  // Inspect comments themselves
  const commentMatches = text.matchAll(/<!--([\s\S]*?)-->|\/\*([\s\S]*?)\*\/|(?:\/\/|#)(.*)$/gm);
  for (const cm of commentMatches) {
    const c = cm[1] || cm[2] || cm[3] || '';
    if (PROTECTIVE_PATTERNS.some((p) => p.test(c))) return true;
  }
  return false;
}

// ============================================================================
// CLIENT-SIDE SCAN RUNNER WITH CUMULATIVE WEIGHTING & THRESHOLD MAPPING
// ============================================================================

/**
 * Computes a client-side Tier-1 security scan:
 * - Cumulatively sums weights of all unique matched regex rules
 * - Accurately maps risk_score to intended thresholds: Safe (<20), Warn (20-69), Hostile (70+)
 * - Persists matched snippets and rule identifiers in flagged_keyphrases
 * - Populates distinct attack categories (Instruction, Role, Source, Social, Extraction)
 */
export function runClientScan(prompt: string, modelOutput?: string | null): ScanResult {
  const startTime = performance.now();
  const matchedRuleIds: string[] = [];
  const flaggedKeyphrases: string[] = [];
  const attackCategoriesSet = new Set<string>();

  let cumulativeWeight = 0;
  let canaryDetected = false;
  let canarySignature: string | null = null;

  // Text candidates: raw prompt, plus model output if provided
  const targetText = modelOutput ? `${prompt}\n---OUTPUT---\n${modelOutput}` : prompt;

  // 0. Protective safety statement check (e.g. "do not change guildlines", "never bypass rules", "/* do not change guidelines */")
  if (isProtectiveSafetyStatement(targetText)) {
    const hasCanary = /Secret-Canary:\s*([a-f0-9\-]{8,36})/i.test(targetText);
    const hasExplicitJailbreak = /\b(?:dan|jailbreak|developer\s+mode|<\|im_start\|>|<<sys>>)\b/i.test(targetText);
    
    // Check if there are non-protective hostile comments
    let hasHostileComment = false;
    const commentMatches = targetText.matchAll(/<!--([\s\S]*?)-->|\/\*([\s\S]*?)\*\/|(?:\/\/|#)(.*)$/gm);
    for (const cm of commentMatches) {
      const cContent = cm[1] || cm[2] || cm[3] || '';
      if (!isProtectiveSafetyStatement(cContent) && /\b(?:system\s+override|jailbreak|dan|unrestricted|bypass\s+all|ignore\s+all)\b/i.test(cContent)) {
        hasHostileComment = true;
        break;
      }
    }

    if (!hasCanary && !hasExplicitJailbreak && !hasHostileComment) {
      return {
        risk_score: 0.0,
        is_hostile: false,
        risk_tier: 'SAFE',
        recommended_action: 'ALLOW',
        flagged_keyphrases: ['[Safety-Preserving Directive: Guidelines protected]'],
        matched_rule_ids: [],
        attack_categories: [],
        scan_latency_ms: Math.round((performance.now() - startTime) * 1000) / 1000,
        canary_detected: false,
        canary_leak_signature: null,
        prompt_hash_for_vector_db: generatePromptHash(prompt),
        attack_type: null,
        tier2_triggered: false
      };
    }
  }

  // 1. Iterate over all client scan rules (case-insensitive & multi-line)
  for (const rule of CLIENT_SCAN_RULES) {
    const match = targetText.match(rule.pattern);
    if (match) {
      // Check if the matched directive is preceded by a negation phrase (e.g. "do not ignore instructions", "never bypass rules")
      const matchIdx = match.index ?? -1;
      if (matchIdx >= 0) {
        const preceding = targetText.slice(Math.max(0, matchIdx - 35), matchIdx).toLowerCase();
        if (/\b(?:do\s+not|don'?t|dont|never|cannot|can'?t|cant|should\s+not|shouldn'?t|must\s+not|mustn'?t|refrain\s+from|refuse\s+to|avoid|forbidden\s+to|prohibited\s+from|not\s+allowed\s+to)\s*(?:set|setting|make|making|switch|switching|turn|turning|toggle|toggling|change|changing|configure|configuring|update|updating)?\s*$/i.test(preceding)) {
          continue;
        }
      }
      if ((rule.rule_id === 'OBF001' || rule.rule_id === 'OBF002' || rule.rule_id === 'OBF003') && isProtectiveSafetyStatement(match[0])) {
        continue;
      }

      matchedRuleIds.push(rule.rule_id);
      cumulativeWeight += rule.weight;
      attackCategoriesSet.add(rule.category);

      // Extract matched snippet (max 60 chars)
      const matchedSnippet = match[0].trim().slice(0, 60);
      flaggedKeyphrases.push(`[${rule.category}: ${rule.rule_id}] ${matchedSnippet}`);

      if (rule.rule_id === 'EXT003' && match[1]) {
        canaryDetected = true;
        canarySignature = match[1];
      }
    }
  }

  // 2. Direct Canary Token Leak Check in model output or prompt
  const canaryMatch = targetText.match(/Secret-Canary:\s*([a-f0-9\-]{8,36})/i);
  if (canaryMatch && !canaryDetected) {
    canaryDetected = true;
    canarySignature = canaryMatch[1];
    cumulativeWeight = 100.0;
    matchedRuleIds.push('EXT003');
    attackCategoriesSet.add('Extraction');
    flaggedKeyphrases.push(`[CANARY LEAK DETECTED: ${canarySignature}]`);
  }

  // 3. Normalize & cap cumulative risk score (0.0 - 100.0)
  const riskScore = Math.min(100.0, Math.round(cumulativeWeight * 10) / 10);

  // 4. Strict mapping to intended tier thresholds:
  // Safe: < 20
  // Warn: 20 <= score < 70
  // Hostile: >= 70
  let riskTier: 'SAFE' | 'WARN' | 'HOSTILE';
  let recommendedAction: 'ALLOW' | 'REVIEW' | 'BLOCK';
  let isHostile: boolean;

  if (riskScore < 20.0) {
    riskTier = 'SAFE';
    recommendedAction = 'ALLOW';
    isHostile = false;
  } else if (riskScore < 70.0) {
    riskTier = 'WARN';
    recommendedAction = 'REVIEW';
    isHostile = false;
  } else {
    riskTier = 'HOSTILE';
    recommendedAction = 'BLOCK';
    isHostile = true;
  }

  // 5. Generate SHA-256 prompt hash for signature tracking
  const promptHash = generatePromptHash(prompt);
  const latencyMs = Math.round((performance.now() - startTime) * 1000) / 1000;

  return {
    risk_score: riskScore,
    is_hostile: isHostile,
    risk_tier: riskTier,
    recommended_action: recommendedAction,
    flagged_keyphrases: flaggedKeyphrases,
    matched_rule_ids: matchedRuleIds,
    attack_categories: Array.from(attackCategoriesSet).sort(),
    scan_latency_ms: latencyMs,
    canary_detected: canaryDetected,
    canary_leak_signature: canarySignature,
    prompt_hash_for_vector_db: promptHash,
    attack_type: attackCategoriesSet.size > 0 ? Array.from(attackCategoriesSet)[0].toLowerCase() : null,
    tier2_triggered: false
  };
}

/**
 * Fast string hash helper for vector DB signature reference
 */
function generatePromptHash(str: string): string {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash |= 0;
  }
  return Math.abs(hash).toString(16).padStart(16, '0').slice(0, 16);
}
