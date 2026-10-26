import type { MitreMappingConfidence } from './ctiTypes.ts';

export const KNOWN_THREAT_ALIASES: Record<string, { canonicalId: string; canonicalName: string }> = {
  // APT29
  'apt29': { canonicalId: 'APT29', canonicalName: 'APT29 (Cozy Bear)' },
  'cozy bear': { canonicalId: 'APT29', canonicalName: 'APT29 (Cozy Bear)' },
  'midnight blizzard': { canonicalId: 'APT29', canonicalName: 'APT29 (Cozy Bear)' },
  'nobelium': { canonicalId: 'APT29', canonicalName: 'APT29 (Cozy Bear)' },
  'the dukes': { canonicalId: 'APT29', canonicalName: 'APT29 (Cozy Bear)' },

  // FIN7
  'fin7': { canonicalId: 'FIN7', canonicalName: 'FIN7 Syndicate' },
  'carbanak': { canonicalId: 'FIN7', canonicalName: 'FIN7 Syndicate' },
  'navigator group': { canonicalId: 'FIN7', canonicalName: 'FIN7 Syndicate' },

  // Sandworm
  'sandworm': { canonicalId: 'Sandworm', canonicalName: 'Sandworm Team' },
  'voodoo bear': { canonicalId: 'Sandworm', canonicalName: 'Sandworm Team' },
  'telebots': { canonicalId: 'Sandworm', canonicalName: 'Sandworm Team' },
  'blackenergy': { canonicalId: 'Sandworm', canonicalName: 'Sandworm Team' },

  // Lazarus
  'lazarus': { canonicalId: 'Lazarus', canonicalName: 'Lazarus Group' },
  'hidden cobra': { canonicalId: 'Lazarus', canonicalName: 'Lazarus Group' },
  'guardians of peace': { canonicalId: 'Lazarus', canonicalName: 'Lazarus Group' }
};

export const KNOWN_MITRE_TECHNIQUES: Record<string, { id: string; name: string; tactic: string }> = {
  't1190': { id: 'T1190', name: 'Exploit Public-Facing Application', tactic: 'Initial Access' },
  't1059': { id: 'T1059', name: 'Command and Scripting Interpreter', tactic: 'Execution' },
  't1078': { id: 'T1078', name: 'Valid Accounts', tactic: 'Defense Evasion, Persistence' },
  't1068': { id: 'T1068', name: 'Exploitation for Privilege Escalation', tactic: 'Privilege Escalation' },
  't1566': { id: 'T1566', name: 'Phishing', tactic: 'Initial Access' },
  't1046': { id: 'T1046', name: 'Network Service Discovery', tactic: 'Discovery' },
  't1021': { id: 'T1021', name: 'Remote Services', tactic: 'Lateral Movement' },
  't1486': { id: 'T1486', name: 'Data Encrypted for Impact', tactic: 'Impact' }
};

/**
 * Normalizes entity name to canonical ID and alias collection.
 */
export function normalizeEntityIdentity(rawName: string, entityType: string): {
  canonicalId: string;
  displayName: string;
  aliases: string[];
} {
  const clean = rawName.trim();
  const lower = clean.toLowerCase();

  // Check known aliases
  if (KNOWN_THREAT_ALIASES[lower]) {
    const match = KNOWN_THREAT_ALIASES[lower];
    return {
      canonicalId: match.canonicalId,
      displayName: match.canonicalName,
      aliases: [clean, match.canonicalId]
    };
  }

  // CVE normalization
  const cveMatch = clean.match(/cve-\d{4}-\d{4,7}/i);
  if (cveMatch) {
    const cveUpper = cveMatch[0].toUpperCase();
    return {
      canonicalId: cveUpper,
      displayName: cveUpper,
      aliases: [clean, cveUpper]
    };
  }

  // Computer System normalization (e.g. "Computer 07", "COMP-07", "host-07")
  const compMatch = clean.match(/(?:computer|comp|host)[ -]?(\d{1,2})/i);
  if (compMatch) {
    const num = compMatch[1].padStart(2, '0');
    return {
      canonicalId: `Computer ${num}`,
      displayName: `Computer ${num}`,
      aliases: [clean, `COMP-${num}`, `Computer ${num}`]
    };
  }

  return {
    canonicalId: clean.replace(/\s+/g, '_'),
    displayName: clean,
    aliases: [clean]
  };
}

/**
 * Maps unstructured technique descriptions or identifiers to MITRE ATT&CK.
 */
export function normalizeMitreTechnique(rawText: string): {
  mitreId?: string;
  techniqueName?: string;
  tactic?: string;
  confidence: MitreMappingConfidence;
} {
  const clean = rawText.trim();
  const lower = clean.toLowerCase();

  // Explicit T-code match
  const tCodeMatch = clean.match(/T\d{4}(?:\.\d{3})?/i);
  if (tCodeMatch) {
    const code = tCodeMatch[0].toUpperCase();
    const info = KNOWN_MITRE_TECHNIQUES[code.toLowerCase()];
    return {
      mitreId: code,
      techniqueName: info?.name || 'MITRE ATT&CK Technique',
      tactic: info?.tactic || 'General',
      confidence: 'CONFIRMED'
    };
  }

  // Keyword heuristic matching
  if (lower.includes('public-facing') || lower.includes('exploit application') || lower.includes('remote exploit')) {
    return {
      mitreId: 'T1190',
      techniqueName: 'Exploit Public-Facing Application',
      tactic: 'Initial Access',
      confidence: 'PROBABLE'
    };
  }
  if (lower.includes('scripting') || lower.includes('command interpreter') || lower.includes('powershell') || lower.includes('bash')) {
    return {
      mitreId: 'T1059',
      techniqueName: 'Command and Scripting Interpreter',
      tactic: 'Execution',
      confidence: 'PROBABLE'
    };
  }
  if (lower.includes('valid account') || lower.includes('credential abuse') || lower.includes('stolen password')) {
    return {
      mitreId: 'T1078',
      techniqueName: 'Valid Accounts',
      tactic: 'Defense Evasion, Persistence',
      confidence: 'PROBABLE'
    };
  }

  return {
    confidence: 'UNCONFIRMED'
  };
}
