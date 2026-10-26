import type { CTIContradiction, ConflictStatus, ExtractedRelationship, SourceReliability } from './ctiTypes.ts';

export const RELIABILITY_SCORES: Record<SourceReliability, number> = {
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
  UNKNOWN: 1
};

/**
 * Detects contradictory claims between new CTI assertions and existing graph knowledge.
 */
export function detectContradiction(params: {
  subjectId: string;
  subjectName: string;
  predicate: string;
  objectId: string;
  objectName: string;
  incomingClaim: {
    documentId: string;
    statement: string;
    assertsPositive: boolean;
    confidence: number;
    timestamp: string;
    sourceReliability: SourceReliability;
  };
  existingClaim: {
    documentId: string;
    statement: string;
    assertsPositive: boolean;
    confidence: number;
    timestamp: string;
    sourceReliability: SourceReliability;
  };
}): CTIContradiction | null {
  // Contradiction exists when polarity differs on the same subject-predicate-object tuple
  if (params.incomingClaim.assertsPositive !== params.existingClaim.assertsPositive) {
    const conflictId = `CONFLICT-${Date.now().toString(36).toUpperCase()}-${Math.random().toString(36).substring(2, 6).toUpperCase()}`;
    return {
      conflictId,
      subjectId: params.subjectId,
      subjectName: params.subjectName,
      predicate: params.predicate,
      objectId: params.objectId,
      objectName: params.objectName,
      claimA: params.existingClaim,
      claimB: params.incomingClaim,
      status: 'OPEN',
      severity: params.incomingClaim.confidence > 0.8 || params.existingClaim.confidence > 0.8 ? 'HIGH' : 'MEDIUM',
      detectedAt: new Date().toISOString()
    };
  }
  return null;
}

/**
 * Evaluates and reconciles contradictory claims based on source reliability,
 * temporal recency, and corroboration strength. Never deletes conflicting evidence.
 */
export function reconcileContradiction(conflict: CTIContradiction): {
  reconciledConflict: CTIContradiction;
  actionTaken: 'SUPERSEDE_A' | 'SUPERSEDE_B' | 'KEEP_UNRESOLVED';
  winningClaimStatement?: string;
} {
  const { claimA, claimB } = conflict;
  const scoreA = RELIABILITY_SCORES[claimA.sourceReliability] * 10 + claimA.confidence * 5;
  const scoreB = RELIABILITY_SCORES[claimB.sourceReliability] * 10 + claimB.confidence * 5;

  const timeA = new Date(claimA.timestamp).getTime();
  const timeB = new Date(claimB.timestamp).getTime();
  const timeDiffDays = (timeB - timeA) / (1000 * 60 * 60 * 24);

  const bHasSupersedingIntent = 
    claimB.statement.toLowerCase().includes('superseded') ||
    claimB.statement.toLowerCase().includes('patched') ||
    claimB.statement.toLowerCase().includes('immune') ||
    claimB.statement.toLowerCase().includes('remediated') ||
    claimB.statement.toLowerCase().includes('resolved') ||
    (!claimB.assertsPositive && claimA.assertsPositive);

  // If claim B is an authoritative vendor patch/supersession bulletin that is as recent or newer than claim A
  if (bHasSupersedingIntent && timeDiffDays >= -0.1 && RELIABILITY_SCORES[claimB.sourceReliability] >= RELIABILITY_SCORES[claimA.sourceReliability]) {
    return {
      reconciledConflict: {
        ...conflict,
        status: 'RESOLVED',
        resolvedAt: new Date().toISOString(),
        winningClaim: 'B',
        resolutionNotes: `Claim B from ${claimB.documentId} supersedes prior claim A: authoritative mitigation/patch bulletin verified (${claimB.sourceReliability} reliability, +${Math.max(0, Math.round(timeDiffDays))} days).`
      },
      actionTaken: 'SUPERSEDE_A',
      winningClaimStatement: claimB.statement
    };
  }

  // If claim B is generally newer with high or equal reliability
  if (timeDiffDays > 0.5 && RELIABILITY_SCORES[claimB.sourceReliability] >= RELIABILITY_SCORES[claimA.sourceReliability]) {
    return {
      reconciledConflict: {
        ...conflict,
        status: 'RESOLVED',
        resolvedAt: new Date().toISOString(),
        winningClaim: 'B',
        resolutionNotes: `Claim B from ${claimB.documentId} supersedes older claim A due to authoritative recency (+${Math.round(timeDiffDays)} days).`
      },
      actionTaken: 'SUPERSEDE_A',
      winningClaimStatement: claimB.statement
    };
  }

  // If claim A is from an authoritative official advisory while B is unverified low-confidence
  if (scoreA - scoreB >= 10) {
    return {
      reconciledConflict: {
        ...conflict,
        status: 'RESOLVED',
        resolvedAt: new Date().toISOString(),
        winningClaim: 'A',
        resolutionNotes: `Claim A retained as authoritative (${claimA.sourceReliability} reliability). Claim B flagged as uncorroborated.`
      },
      actionTaken: 'SUPERSEDE_B',
      winningClaimStatement: claimA.statement
    };
  }

  // Ambiguous: maintain OPEN/UNRESOLVED status and preserve both evidence streams
  return {
    reconciledConflict: {
      ...conflict,
      status: 'UNRESOLVED',
      resolutionNotes: 'Evidence remains balanced. Both conflicting intelligence claims preserved for analyst review.'
    },
    actionTaken: 'KEEP_UNRESOLVED'
  };
}
