export type TemporalStatus = 'ACTIVE' | 'AGING' | 'STALE' | 'EXPIRED' | 'SUPERSEDED';

export type ConflictStatus = 'OPEN' | 'REVIEWING' | 'RESOLVED' | 'SUPERSEDED' | 'UNRESOLVED';

export type SourceReliability = 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';

export type MitreMappingConfidence = 'CONFIRMED' | 'PROBABLE' | 'UNCONFIRMED';

export interface CTIDocument {
  documentId: string;
  title: string;
  source: string;
  sourceType: 'REPORT' | 'ADVISORY' | 'INCIDENT' | 'FEED' | 'RESEARCH';
  publishedAt: string;
  observedAt: string;
  ingestedAt: string;
  lastSeenAt: string;
  confidence: number;
  sourceReliability: SourceReliability;
  classification: 'PUBLIC' | 'INTERNAL' | 'RESTRICTED';
  contentHash: string;
  status: 'ACTIVE' | 'ARCHIVED';
  rawText: string;
  extractedEntitiesCount?: number;
  extractedRelationsCount?: number;
}

export interface ExtractedEntity {
  canonicalId: string;
  displayName: string;
  entityType: 'ThreatActor' | 'Campaign' | 'Malware' | 'Tool' | 'Vulnerability' | 'Technique' | 'Software' | 'Computer' | 'IP' | 'Mitigation' | 'Indicator';
  aliases: string[];
  sourceDocumentIds: string[];
  confidence: number;
  mitreId?: string;
  mitreConfidence?: MitreMappingConfidence;
  firstSeen: string;
  lastSeen: string;
  temporalStatus: TemporalStatus;
  properties?: Record<string, any>;
}

export interface ExtractedRelationship {
  id: string;
  sourceId: string;
  targetId: string;
  relationshipType: 'USES' | 'DEPLOYS' | 'EXPLOITS' | 'AFFECTS' | 'RUNS_ON' | 'TARGETS' | 'MITIGATED_BY' | 'COMMUNICATES_WITH';
  confidence: number;
  currentWeight: number;
  sourceDocumentIds: string[];
  evidenceText: string;
  createdAt: string;
  lastObservedAt: string;
  temporalStatus: TemporalStatus;
  corroborationCount: number;
  recencyFactor: number;
  sourceReliability: SourceReliability;
  conflictStatus?: ConflictStatus;
  conflictId?: string;
  isSuperseded?: boolean;
}

export interface CTIContradiction {
  conflictId: string;
  subjectId: string;
  subjectName: string;
  predicate: string;
  objectId: string;
  objectName: string;
  claimA: {
    documentId: string;
    statement: string;
    assertsPositive: boolean;
    confidence: number;
    timestamp: string;
    sourceReliability: SourceReliability;
  };
  claimB: {
    documentId: string;
    statement: string;
    assertsPositive: boolean;
    confidence: number;
    timestamp: string;
    sourceReliability: SourceReliability;
  };
  status: ConflictStatus;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  detectedAt: string;
  resolvedAt?: string;
  resolutionNotes?: string;
  winningClaim?: 'A' | 'B' | 'NONE';
}

export interface CTIReconciliationEvent {
  id: string;
  timestamp: string;
  eventType: 'DOCUMENT_INGESTED' | 'ENTITY_DISCOVERED' | 'RELATION_CORROBORATED' | 'TEMPORAL_DECAY_APPLIED' | 'CONFLICT_DETECTED' | 'CONFLICT_RESOLVED' | 'INTELLIGENCE_SUPERSEDED';
  documentId?: string;
  entityId?: string;
  relationId?: string;
  conflictId?: string;
  title: string;
  description: string;
  confidenceChange?: { before: number; after: number };
}

export interface TemporalDecayConfig {
  enabled: boolean;
  halfLifeDays: number;
  minimumWeight: number;
  agingThresholdDays: number;
  staleThresholdDays: number;
  expiredThresholdDays: number;
}
