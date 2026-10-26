import fs from 'fs';
import path from 'path';
import type { 
  CTIDocument, 
  ExtractedEntity, 
  ExtractedRelationship, 
  CTIContradiction, 
  CTIReconciliationEvent,
  TemporalDecayConfig
} from './ctiTypes.ts';
import { normalizeEntityIdentity, normalizeMitreTechnique } from './ctiNormalizer.ts';
import { calculateEdgeWeight, DEFAULT_DECAY_CONFIG } from './ctiScoring.ts';
import { detectContradiction, reconcileContradiction } from './ctiContradiction.ts';
import { SYNTHETIC_CTI_REPORTS } from './syntheticReports.ts';
import { GoogleGenAI } from '@google/genai';

export class CTIReconciler {
  private documents: Map<string, CTIDocument> = new Map();
  private entities: Map<string, ExtractedEntity> = new Map();
  private relationships: Map<string, ExtractedRelationship> = new Map();
  private contradictions: Map<string, CTIContradiction> = new Map();
  private timelineEvents: CTIReconciliationEvent[] = [];
  private decayConfig: TemporalDecayConfig = { ...DEFAULT_DECAY_CONFIG };
  private aiClient: GoogleGenAI | null = null;
  private persistenceFile = path.join(process.cwd(), 'data/cti_store.json');

  constructor() {
    const apiKey = process.env.GEMINI_API_KEY;
    if (apiKey) {
      try {
        this.aiClient = new GoogleGenAI({ apiKey });
      } catch (e) {
        this.aiClient = null;
      }
    }

    // Try loading persistent state from disk
    const loaded = this.loadFromDisk();
    if (!loaded || this.documents.size === 0) {
      // Pre-populate and extract entities/relationships/contradictions from synthetic demonstration reports
      for (const doc of SYNTHETIC_CTI_REPORTS) {
        this.ingestDocumentInternal(doc.rawText, doc);
      }
      this.saveToDisk();
    }
  }

  public saveToDisk(): void {
    try {
      const dataDir = path.dirname(this.persistenceFile);
      if (!fs.existsSync(dataDir)) {
        fs.mkdirSync(dataDir, { recursive: true });
      }
      const serialized = {
        documents: Array.from(this.documents.entries()),
        entities: Array.from(this.entities.entries()),
        relationships: Array.from(this.relationships.entries()),
        contradictions: Array.from(this.contradictions.entries()),
        timelineEvents: this.timelineEvents
      };
      fs.writeFileSync(this.persistenceFile, JSON.stringify(serialized, null, 2), 'utf-8');
    } catch (e) {
      console.warn('[CTI Store] Failed to save state to disk:', e);
    }
  }

  public loadFromDisk(): boolean {
    try {
      if (fs.existsSync(this.persistenceFile)) {
        const raw = fs.readFileSync(this.persistenceFile, 'utf-8');
        const parsed = JSON.parse(raw);
        if (parsed.documents && Array.isArray(parsed.documents)) {
          this.documents = new Map(parsed.documents);
          this.entities = new Map(parsed.entities || []);
          this.relationships = new Map(parsed.relationships || []);
          this.contradictions = new Map(parsed.contradictions || []);
          this.timelineEvents = parsed.timelineEvents || [];
          return true;
        }
      }
    } catch (e) {
      console.warn('[CTI Store] Failed to restore state from disk:', e);
    }
    return false;
  }

  public getDocuments(): CTIDocument[] {
    return Array.from(this.documents.values()).sort((a, b) => 
      new Date(b.publishedAt).getTime() - new Date(a.publishedAt).getTime()
    );
  }

  public getDocument(id: string): CTIDocument | undefined {
    return this.documents.get(id);
  }

  public getEntities(): ExtractedEntity[] {
    return Array.from(this.entities.values());
  }

  public getRelationships(): ExtractedRelationship[] {
    return Array.from(this.relationships.values());
  }

  public getContradictions(): CTIContradiction[] {
    return Array.from(this.contradictions.values());
  }

  public getTimelineEvents(): CTIReconciliationEvent[] {
    return [...this.timelineEvents].sort((a, b) => 
      new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
    );
  }

  public getDecayConfig(): TemporalDecayConfig {
    return { ...this.decayConfig };
  }

  public updateDecayConfig(config: Partial<TemporalDecayConfig>): TemporalDecayConfig {
    this.decayConfig = { ...this.decayConfig, ...config };
    this.recalculateAllWeights();
    return this.decayConfig;
  }

  /**
   * Recalculates dynamic weights and temporal status for all relationships in the graph.
   */
  public recalculateAllWeights(): void {
    const now = new Date();
    this.relationships.forEach(rel => {
      const calc = calculateEdgeWeight({
        baseConfidence: rel.confidence,
        lastObservedDate: rel.lastObservedAt,
        corroborationCount: rel.corroborationCount,
        sourceReliability: rel.sourceReliability,
        isSuperseded: rel.isSuperseded,
        config: this.decayConfig,
        now
      });
      rel.currentWeight = calc.weight;
      rel.recencyFactor = calc.recencyFactor;
      rel.temporalStatus = calc.temporalStatus;
    });
    this.saveToDisk();
  }

  /**
   * Multi-format preprocessing: Parses STIX 2.1 bundles, HTML documents, or plain text
   */
  private preprocessInput(rawInput: any, metadata: Partial<CTIDocument>): {
    extractedText: string;
    detectedFormat: string;
    stixBundle?: any;
    titleOverride?: string;
  } {
    // 1. Check if input is a STIX 2.1 JSON bundle (either object or JSON string)
    let parsedJson: any = null;
    if (typeof rawInput === 'object' && rawInput !== null) {
      parsedJson = rawInput;
    } else if (typeof rawInput === 'string' && (rawInput.trim().startsWith('{') || rawInput.trim().startsWith('['))) {
      try {
        parsedJson = JSON.parse(rawInput.trim());
      } catch (e) {
        // Not JSON
      }
    }

    if (parsedJson && (parsedJson.type === 'bundle' || Array.isArray(parsedJson.objects))) {
      const objects = parsedJson.objects || [];
      const lines: string[] = [
        `[STIX 2.1 THREAT BUNDLE INGESTION - ID: ${parsedJson.id || 'bundle-custom'}]`
      ];

      for (const obj of objects) {
        if (obj.type === 'threat-actor') {
          lines.push(`Threat Actor: ${obj.name || obj.id} (Aliases: ${(obj.aliases || []).join(', ')})`);
          if (obj.description) lines.push(`Threat Actor Description: ${obj.description}`);
        } else if (obj.type === 'attack-pattern') {
          const extRef = (obj.external_references || []).find((r: any) => r.source_name === 'mitre-attack');
          const mitreId = extRef?.external_id || '';
          lines.push(`Technique: ${mitreId ? mitreId + ' - ' : ''}${obj.name}`);
        } else if (obj.type === 'vulnerability') {
          const extRef = (obj.external_references || []).find((r: any) => r.source_name === 'cve');
          lines.push(`Vulnerability: ${extRef?.external_id || obj.name}`);
          if (obj.description) lines.push(`Vulnerability Description: ${obj.description}`);
        } else if (obj.type === 'relationship') {
          lines.push(`Relationship: ${obj.source_ref} ${obj.relationship_type?.toUpperCase()} ${obj.target_ref}`);
        } else if (obj.type === 'malware' || obj.type === 'tool') {
          lines.push(`Malware/Tool: ${obj.name} (${obj.type})`);
        }
      }

      return {
        extractedText: lines.join('\n'),
        detectedFormat: 'STIX_2.1_BUNDLE',
        stixBundle: parsedJson,
        titleOverride: metadata.title || `STIX 2.1 Bundle: ${parsedJson.id || 'Cyber Threat Feed'}`
      };
    }

    const text = typeof rawInput === 'string' ? rawInput : JSON.stringify(rawInput);

    // 2. HTML parsing
    if (text.includes('<html') || text.includes('<body') || text.includes('</p>') || text.includes('</div>')) {
      const titleMatch = text.match(/<title[^>]*>([^<]+)<\/title>/i);
      const cleanText = text
        .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, ' ')
        .replace(/<style\b[^<]*(?:(?!<\/style>)<[^<]*)*<\/style>/gi, ' ')
        .replace(/<[^>]+>/g, ' ')
        .replace(/&nbsp;/g, ' ')
        .replace(/&amp;/g, '&')
        .replace(/&lt;/g, '<')
        .replace(/&gt;/g, '>')
        .replace(/\s+/g, ' ')
        .trim();

      return {
        extractedText: cleanText,
        detectedFormat: 'HTML_DOCUMENT',
        titleOverride: metadata.title || (titleMatch ? titleMatch[1].trim() : 'CTI HTML Advisory')
      };
    }

    // 3. Plain Text / Markdown
    return {
      extractedText: text,
      detectedFormat: 'PLAIN_TEXT'
    };
  }

  /**
   * Internal ingestion worker used for both initial bootstrap and live requests
   */
  public ingestDocumentInternal(rawInput: any, metadata: Partial<CTIDocument> = {}): {
    document: CTIDocument;
    entitiesAdded: number;
    entitiesUpdated: number;
    relationshipsAdded: number;
    relationshipsUpdated: number;
    duplicatesDetected: number;
    contradictionsDetected: number;
    reconciliationEvents: CTIReconciliationEvent[];
  } {
    const { extractedText, detectedFormat, titleOverride } = this.preprocessInput(rawInput, metadata);

    const documentId = metadata.documentId || `CTI-DOC-${Date.now().toString(36).toUpperCase()}`;
    const publishedAt = metadata.publishedAt || new Date().toISOString();
    const observedAt = metadata.observedAt || publishedAt;
    const nowIso = new Date().toISOString();

    const document: CTIDocument = {
      documentId,
      title: titleOverride || metadata.title || `CTI Security Assessment (${new Date().toLocaleDateString()})`,
      source: metadata.source || `Threat Intelligence Ingestion Engine [${detectedFormat}]`,
      sourceType: metadata.sourceType || 'REPORT',
      publishedAt,
      observedAt,
      ingestedAt: nowIso,
      lastSeenAt: publishedAt,
      confidence: metadata.confidence || 0.88,
      sourceReliability: metadata.sourceReliability || 'HIGH',
      classification: metadata.classification || 'INTERNAL',
      contentHash: `hash-${Date.now()}-${Math.random().toString(36).substring(2, 8)}`,
      status: 'ACTIVE',
      rawText: extractedText
    };

    this.documents.set(documentId, document);

    // Record timeline ingestion event
    this.addTimelineEvent({
      id: `EVT-${Date.now()}-INGEST`,
      timestamp: nowIso,
      eventType: 'DOCUMENT_INGESTED',
      documentId,
      title: `Ingested CTI Report: ${document.title}`,
      description: `Format [${detectedFormat}] parsed into knowledge graph pipeline with ${document.sourceReliability} reliability.`
    });

    let entitiesAdded = 0;
    let entitiesUpdated = 0;
    let relationshipsAdded = 0;
    let relationshipsUpdated = 0;
    let duplicatesDetected = 0;
    let contradictionsDetected = 0;

    // --- Dynamic General-Purpose Entity Extraction ---
    const extractedEntityDrafts = this.parseEntitiesGeneral(extractedText, documentId, publishedAt);

    extractedEntityDrafts.forEach(draft => {
      const existing = this.entities.get(draft.canonicalId);
      if (existing) {
        duplicatesDetected++;
        entitiesUpdated++;
        existing.lastSeen = publishedAt;
        if (!existing.sourceDocumentIds.includes(documentId)) {
          existing.sourceDocumentIds.push(documentId);
        }
        draft.aliases.forEach(alias => {
          if (!existing.aliases.includes(alias)) {
            existing.aliases.push(alias);
          }
        });
        existing.confidence = Math.min(1.0, existing.confidence + 0.05);
      } else {
        entitiesAdded++;
        this.entities.set(draft.canonicalId, draft);
        this.addTimelineEvent({
          id: `EVT-${Date.now()}-ENT-${draft.canonicalId}`,
          timestamp: nowIso,
          eventType: 'ENTITY_DISCOVERED',
          documentId,
          entityId: draft.canonicalId,
          title: `Entity Normalized: ${draft.displayName} (${draft.entityType})`,
          description: `Discovered and registered canonical identity with ${Math.round(draft.confidence * 100)}% baseline confidence.`
        });
      }
    });

    // --- Dynamic Relationship Extraction & Contradiction Detection ---
    const extractedRelDrafts = this.parseRelationshipsGeneral(
      extractedText,
      documentId,
      publishedAt,
      document.sourceReliability,
      extractedEntityDrafts
    );

    const isSupersedingDoc = 
      extractedText.toLowerCase().includes('superseded') || 
      extractedText.toLowerCase().includes('fully patched') ||
      extractedText.toLowerCase().includes('immune to') ||
      extractedText.toLowerCase().includes('mitigation verified');

    extractedRelDrafts.forEach(rel => {
      const relKey = `${rel.sourceId}-${rel.relationshipType}-${rel.targetId}`;
      const existingRel = this.relationships.get(relKey);

      // CRITICAL FIX: Save the previous observation date BEFORE any update
      const priorObservedAt = existingRel ? existingRel.lastObservedAt : publishedAt;

      // If document explicitly asserts target is patched/superseded, do NOT strengthen an active AFFECTS claim!
      if (existingRel) {
        if (!isSupersedingDoc || rel.relationshipType !== 'AFFECTS') {
          relationshipsUpdated++;
          existingRel.corroborationCount += 1;
          existingRel.lastObservedAt = publishedAt;
          if (!existingRel.sourceDocumentIds.includes(documentId)) {
            existingRel.sourceDocumentIds.push(documentId);
          }
          const calc = calculateEdgeWeight({
            baseConfidence: existingRel.confidence,
            lastObservedDate: existingRel.lastObservedAt,
            corroborationCount: existingRel.corroborationCount,
            sourceReliability: document.sourceReliability,
            isSuperseded: existingRel.isSuperseded,
            config: this.decayConfig
          });
          existingRel.currentWeight = calc.weight;
          existingRel.recencyFactor = calc.recencyFactor;
          existingRel.temporalStatus = calc.temporalStatus;

          this.addTimelineEvent({
            id: `EVT-${Date.now()}-REL-CORROB`,
            timestamp: nowIso,
            eventType: 'RELATION_CORROBORATED',
            documentId,
            relationId: relKey,
            title: `Relationship Corroborated: ${rel.sourceId} ${rel.relationshipType} ${rel.targetId}`,
            description: `Corroborated across ${existingRel.corroborationCount} independent documents. Dynamic weight: ${existingRel.currentWeight}.`
          });
        }
      } else {
        relationshipsAdded++;
        this.relationships.set(relKey, rel);
      }

      // Check for supersession / contradictions
      if (isSupersedingDoc) {
        this.relationships.forEach(otherRel => {
          if (otherRel.targetId === rel.targetId && otherRel.relationshipType === 'AFFECTS' && !otherRel.isSuperseded) {
            contradictionsDetected++;
            const contradiction = detectContradiction({
              subjectId: otherRel.sourceId,
              subjectName: otherRel.sourceId,
              predicate: 'AFFECTS',
              objectId: rel.targetId,
              objectName: rel.targetId,
              incomingClaim: {
                documentId,
                statement: `${rel.targetId} is fully patched and immune to ${otherRel.sourceId}`,
                assertsPositive: false,
                confidence: document.confidence,
                timestamp: publishedAt,
                sourceReliability: document.sourceReliability
              },
              existingClaim: {
                documentId: otherRel.sourceDocumentIds[0] || 'PRIOR-REPORT',
                statement: `${otherRel.sourceId} affects and compromises ${rel.targetId}`,
                assertsPositive: true,
                confidence: otherRel.confidence,
                timestamp: priorObservedAt,
                sourceReliability: otherRel.sourceReliability
              }
            });

            if (contradiction) {
              const resolution = reconcileContradiction(contradiction);
              this.contradictions.set(contradiction.conflictId, resolution.reconciledConflict);

              if (resolution.actionTaken === 'SUPERSEDE_A') {
                otherRel.isSuperseded = true;
                otherRel.temporalStatus = 'SUPERSEDED';
                otherRel.conflictStatus = 'SUPERSEDED';
                otherRel.conflictId = contradiction.conflictId;
                otherRel.currentWeight = Number((otherRel.currentWeight * 0.1).toFixed(3));

                this.addTimelineEvent({
                  id: `EVT-${Date.now()}-SUPERSEDE`,
                  timestamp: nowIso,
                  eventType: 'INTELLIGENCE_SUPERSEDED',
                  documentId,
                  conflictId: contradiction.conflictId,
                  title: `Intelligence Superseded: ${otherRel.sourceId} Affects ${rel.targetId}`,
                  description: resolution.reconciledConflict.resolutionNotes || 'Claim superseded by authoritative vendor advisory.'
                });
              }
            }
          }
        });
      }
    });

    document.extractedEntitiesCount = extractedEntityDrafts.length;
    document.extractedRelationsCount = extractedRelDrafts.length;

    this.saveToDisk();

    return {
      document,
      entitiesAdded,
      entitiesUpdated,
      relationshipsAdded,
      relationshipsUpdated,
      duplicatesDetected,
      contradictionsDetected,
      reconciliationEvents: this.getTimelineEvents().slice(0, 5)
    };
  }

  /**
   * Public asynchronous ingestion endpoint
   */
  public async ingestDocument(rawInput: any, metadata: Partial<CTIDocument> = {}): Promise<{
    document: CTIDocument;
    entitiesAdded: number;
    entitiesUpdated: number;
    relationshipsAdded: number;
    relationshipsUpdated: number;
    duplicatesDetected: number;
    contradictionsDetected: number;
    reconciliationEvents: CTIReconciliationEvent[];
  }> {
    return this.ingestDocumentInternal(rawInput, metadata);
  }

  private addTimelineEvent(event: CTIReconciliationEvent): void {
    this.timelineEvents.unshift(event);
    if (this.timelineEvents.length > 150) {
      this.timelineEvents.pop();
    }
  }

  /**
   * General-Purpose Semantic Entity Extraction (Dynamic Regex + Pattern Matching)
   */
  private parseEntitiesGeneral(text: string, documentId: string, timestamp: string): ExtractedEntity[] {
    const entitiesMap = new Map<string, ExtractedEntity>();

    // 1. CVE Regex: CVE-YYYY-NNNNN
    const cveMatches = text.match(/\bCVE-\d{4}-\d{4,8}\b/gi) || [];
    for (const cve of cveMatches) {
      const upper = cve.toUpperCase();
      const norm = normalizeEntityIdentity(upper, 'Vulnerability');
      entitiesMap.set(norm.canonicalId, {
        canonicalId: norm.canonicalId,
        displayName: norm.canonicalId,
        entityType: 'Vulnerability',
        aliases: norm.aliases,
        sourceDocumentIds: [documentId],
        confidence: 0.98,
        firstSeen: timestamp,
        lastSeen: timestamp,
        temporalStatus: 'ACTIVE'
      });
    }

    // 2. MITRE Technique Regex: T1xxx[.xxx]
    const mitreMatches = text.match(/\bT\d{4}(?:\.\d{3})?\b/gi) || [];
    for (const tech of mitreMatches) {
      const upper = tech.toUpperCase();
      const mitre = normalizeMitreTechnique(upper);
      entitiesMap.set(upper, {
        canonicalId: upper,
        displayName: mitre.techniqueName ? `${upper} (${mitre.techniqueName})` : upper,
        entityType: 'Technique',
        aliases: [upper],
        sourceDocumentIds: [documentId],
        confidence: 0.94,
        mitreId: upper,
        mitreConfidence: mitre.confidence,
        firstSeen: timestamp,
        lastSeen: timestamp,
        temporalStatus: 'ACTIVE'
      });
    }

    // 3. Computer / Host / Server Assets: "Computer XX", "Host XX", "Server XX"
    const hostMatches = text.match(/\b(?:Computer|Host|Server)\s*\d{1,3}\b/gi) || [];
    for (const host of hostMatches) {
      const norm = normalizeEntityIdentity(host, 'Computer');
      entitiesMap.set(norm.canonicalId, {
        canonicalId: norm.canonicalId,
        displayName: norm.displayName,
        entityType: 'Computer',
        aliases: norm.aliases,
        sourceDocumentIds: [documentId],
        confidence: 0.95,
        firstSeen: timestamp,
        lastSeen: timestamp,
        temporalStatus: 'ACTIVE'
      });
    }

    // 4. Known Threat Actors Catalog (APT, FIN, Bears, Lazarus, etc.)
    const actorPatterns = [
      { pattern: /\b(?:APT\d+|Cozy Bear|Midnight Blizzard|Nobelium)\b/gi, canonical: 'APT29', type: 'ThreatActor' },
      { pattern: /\b(?:FIN7|Carbanak|Navigator Group)\b/gi, canonical: 'FIN7', type: 'ThreatActor' },
      { pattern: /\b(?:Lazarus(?:\s+Group)?|Hidden Cobra)\b/gi, canonical: 'Lazarus', type: 'ThreatActor' },
      { pattern: /\b(?:Volt Typhoon|Bronze Silhouette)\b/gi, canonical: 'Volt Typhoon', type: 'ThreatActor' },
      { pattern: /\b(?:Sandworm|Voodoo Bear|Telebots)\b/gi, canonical: 'Sandworm', type: 'ThreatActor' },
      { pattern: /\b(?:Fancy Bear|APT28|Sednit)\b/gi, canonical: 'APT28', type: 'ThreatActor' },
      { pattern: /\b(?:LockBit|BlackCat|Scattered Spider)\b/gi, canonical: 'LockBit', type: 'ThreatActor' }
    ];

    for (const { pattern, canonical, type } of actorPatterns) {
      if (pattern.test(text)) {
        const norm = normalizeEntityIdentity(canonical, type);
        entitiesMap.set(norm.canonicalId, {
          canonicalId: norm.canonicalId,
          displayName: norm.displayName,
          entityType: 'ThreatActor',
          aliases: norm.aliases,
          sourceDocumentIds: [documentId],
          confidence: 0.92,
          firstSeen: timestamp,
          lastSeen: timestamp,
          temporalStatus: 'ACTIVE'
        });
      }
    }

    // 5. Malware / Software / Framework Families
    const malwarePatterns = [
      { pattern: /\b(?:Log4j|Log4Shell)\b/gi, name: 'Log4Shell', type: 'Vulnerability' },
      { pattern: /\b(?:Cobalt Strike)\b/gi, name: 'Cobalt Strike', type: 'Tool' },
      { pattern: /\b(?:Mimikatz)\b/gi, name: 'Mimikatz', type: 'Tool' },
      { pattern: /\b(?:PostgreSQL)\b/gi, name: 'PostgreSQL', type: 'Software' },
      { pattern: /\b(?:Spring Boot|Spring Security)\b/gi, name: 'Spring Boot', type: 'Software' }
    ];

    for (const { pattern, name, type } of malwarePatterns) {
      if (pattern.test(text) && !entitiesMap.has(name)) {
        entitiesMap.set(name, {
          canonicalId: name,
          displayName: name,
          entityType: type as any,
          aliases: [name],
          sourceDocumentIds: [documentId],
          confidence: 0.90,
          firstSeen: timestamp,
          lastSeen: timestamp,
          temporalStatus: 'ACTIVE'
        });
      }
    }

    return Array.from(entitiesMap.values());
  }

  /**
   * General-Purpose Semantic Relationship Extraction (Grammar & Proximity Derivation)
   */
  private parseRelationshipsGeneral(
    text: string,
    documentId: string,
    timestamp: string,
    sourceReliability: any,
    extractedEntities: ExtractedEntity[]
  ): ExtractedRelationship[] {
    const relationships: ExtractedRelationship[] = [];
    const relKeys = new Set<string>();

    const threatActors = extractedEntities.filter(e => e.entityType === 'ThreatActor');
    const techniques = extractedEntities.filter(e => e.entityType === 'Technique');
    const vulnerabilities = extractedEntities.filter(e => e.entityType === 'Vulnerability');
    const computers = extractedEntities.filter(e => e.entityType === 'Computer');

    const addRel = (sourceId: string, relType: any, targetId: string, evidence: string, conf = 0.92) => {
      const key = `${sourceId}-${relType}-${targetId}`;
      if (relKeys.has(key)) return;
      relKeys.add(key);

      const weightCalc = calculateEdgeWeight({
        baseConfidence: conf,
        lastObservedDate: timestamp,
        corroborationCount: 1,
        sourceReliability,
        config: this.decayConfig
      });

      relationships.push({
        id: `REL-${documentId}-${sourceId}-${relType}-${targetId}`.replace(/\s+/g, '_'),
        sourceId,
        targetId,
        relationshipType: relType,
        confidence: conf,
        currentWeight: weightCalc.weight,
        sourceDocumentIds: [documentId],
        evidenceText: evidence,
        createdAt: timestamp,
        lastObservedAt: timestamp,
        temporalStatus: weightCalc.temporalStatus,
        corroborationCount: 1,
        recencyFactor: weightCalc.recencyFactor,
        sourceReliability
      });
    };

    // Split text into syntactic sentences to enforce claim-level proximity and eliminate false combinations
    const sentences = text
      .split(/(?<=[.?!;])\s+|\n+/)
      .map(s => s.trim())
      .filter(s => s.length > 8);

    for (const sentence of sentences) {
      const sLower = sentence.toLowerCase();

      // Check entities actually present in this single sentence
      const sActors = threatActors.filter(a => 
        sLower.includes(a.canonicalId.toLowerCase()) || 
        a.aliases.some(alias => sLower.includes(alias.toLowerCase()))
      );
      const sTechniques = techniques.filter(t => 
        sLower.includes(t.canonicalId.toLowerCase()) || 
        sLower.includes(t.displayName.toLowerCase())
      );
      const sVulns = vulnerabilities.filter(v => 
        sLower.includes(v.canonicalId.toLowerCase()) || 
        v.aliases.some(alias => sLower.includes(alias.toLowerCase()))
      );
      const sComputers = computers.filter(c => 
        sLower.includes(c.canonicalId.toLowerCase()) || 
        c.aliases.some(alias => sLower.includes(alias.toLowerCase()))
      );

      // Semantic Predicate Trigger Guards
      const hasActionVerb = /\b(?:use|used|uses|using|leverag|utiliz|deploy|tactic|technique|campaign|execut|exploit|adopt|employ|associated|observed|attributed)\b/i.test(sentence);
      const hasExploitVerb = /\b(?:exploit|target|weaponiz|vulnerabilit|cve|flaw|bug|leverag|via|through|injection|bypass|compromis)\b/i.test(sentence);
      const hasCompromiseVerb = /\b(?:affect|target|compromis|infect|detected on|found on|host|system|server|machine|unpatched|running on|vulnerable|endpoint|injected)\b/i.test(sentence);
      const hasMitigationVerb = /\b(?:mitigat|patch|fixed|remediat|secur|upgrad|addressed|resolved|bulletin|workaround)\b/i.test(sentence);

      // 1. ThreatActor -> USES -> Technique (requires co-occurrence in single sentence + action verb)
      if (hasActionVerb || sActors.length > 0) {
        for (const actor of sActors) {
          for (const tech of sTechniques) {
            addRel(
              actor.canonicalId,
              'USES',
              tech.canonicalId,
              sentence,
              0.93
            );
          }
        }
      }

      // 2. Technique -> EXPLOITS -> Vulnerability (requires co-occurrence in single sentence + exploit verb)
      if (hasExploitVerb || sTechniques.length > 0) {
        for (const tech of sTechniques) {
          for (const vuln of sVulns) {
            addRel(
              tech.canonicalId,
              'EXPLOITS',
              vuln.canonicalId,
              sentence,
              0.95
            );
          }
        }
      }

      // 3. Vulnerability -> AFFECTS -> Computer (requires co-occurrence in single sentence + compromise verb)
      if (hasCompromiseVerb || sVulns.length > 0) {
        for (const vuln of sVulns) {
          for (const comp of sComputers) {
            addRel(
              vuln.canonicalId,
              'AFFECTS',
              comp.canonicalId,
              sentence,
              0.96
            );
          }
        }
      }

      // 4. Mitigation -> MITIGATED_BY -> Vulnerability (requires co-occurrence in single sentence + mitigation verb)
      if (hasMitigationVerb) {
        for (const comp of sComputers) {
          for (const vuln of sVulns) {
            const patchId = `Mitigation-${comp.canonicalId.replace(/\s+/g, '')}`;
            addRel(
              patchId,
              'MITIGATED_BY',
              vuln.canonicalId,
              sentence,
              0.96
            );
          }
        }
      }
    }

    return relationships;
  }

  /**
   * Synchronize CTI Intelligence into the Authoritative Application Graph (Live Topology)
   */
  public syncWithGraphState(graphState: { nodes: any[]; edges: any[] }): {
    nodesAddedOrUpdated: number;
    edgesAddedOrUpdated: number;
    remediatedVulnIds: string[];
    restoredHosts: string[];
  } {
    let nodesAddedOrUpdated = 0;
    let edgesAddedOrUpdated = 0;
    const remediatedVulnIds: string[] = [];
    const restoredHosts: string[] = [];

    // 1. Sync Entities (ThreatActors, Techniques) as nodes in graphState if not present
    for (const entity of this.entities.values()) {
      let existingNode = graphState.nodes.find(n => n.id === entity.canonicalId);
      if (!existingNode) {
        graphState.nodes.push({
          id: entity.canonicalId,
          properties: {
            label: entity.entityType,
            name: entity.displayName,
            description: `CTI Intelligence entity (${entity.entityType})`,
            confidence: entity.confidence,
            temporalStatus: entity.temporalStatus,
            dataset: 'CTI Research Sync'
          }
        });
        nodesAddedOrUpdated++;
      }
    }

    // 2. Sync Relationships as edges in graphState (with edge property updates on decay)
    for (const rel of this.relationships.values()) {
      const existingEdge = graphState.edges.find(
        e => ((e.from === rel.sourceId || e.source === rel.sourceId) &&
              (e.to === rel.targetId || e.target === rel.targetId) &&
              e.label === rel.relationshipType)
      );
      if (!existingEdge) {
        const fromNodeExists = graphState.nodes.some(n => n.id === rel.sourceId);
        const toNodeExists = graphState.nodes.some(n => n.id === rel.targetId);
        if (fromNodeExists && toNodeExists) {
          graphState.edges.push({
            from: rel.sourceId,
            to: rel.targetId,
            label: rel.relationshipType,
            weight: rel.currentWeight,
            temporalStatus: rel.temporalStatus,
            corroborationCount: rel.corroborationCount,
            recencyFactor: rel.recencyFactor,
            lastObservedAt: rel.lastObservedAt,
            properties: {
              weight: rel.currentWeight,
              temporalStatus: rel.temporalStatus,
              corroborationCount: rel.corroborationCount,
              recencyFactor: rel.recencyFactor,
              lastObservedAt: rel.lastObservedAt
            }
          });
          edgesAddedOrUpdated++;
        }
      } else {
        // Crucial: Update existing edge properties when temporal weight or decay changes!
        existingEdge.weight = rel.currentWeight;
        existingEdge.temporalStatus = rel.temporalStatus;
        existingEdge.corroborationCount = rel.corroborationCount;
        existingEdge.recencyFactor = rel.recencyFactor;
        existingEdge.lastObservedAt = rel.lastObservedAt;
        if (!existingEdge.properties) existingEdge.properties = {};
        existingEdge.properties.weight = rel.currentWeight;
        existingEdge.properties.temporalStatus = rel.temporalStatus;
        existingEdge.properties.corroborationCount = rel.corroborationCount;
        existingEdge.properties.recencyFactor = rel.recencyFactor;
        existingEdge.properties.lastObservedAt = rel.lastObservedAt;
        edgesAddedOrUpdated++;
      }
    }

    // 3. Resolve Superseded / Fully Patched Contradictions directly in the Graph
    for (const contradiction of this.contradictions.values()) {
      if (contradiction.status === 'RESOLVED' && contradiction.winningClaim === 'B') {
        const targetHost = contradiction.objectId; // e.g. "Computer 14"
        const vulnId = contradiction.subjectId; // e.g. "CVE-2021-44228"

        // Locate Vulnerability node in graph
        const vulnNode = graphState.nodes.find(n => n.id === vulnId || (n.properties?.name && n.properties.name.includes(vulnId)));
        if (vulnNode && vulnNode.properties.status !== 'SELF_HEALED') {
          vulnNode.properties.status = 'SELF_HEALED';
          vulnNode.properties.resolved_at = contradiction.resolvedAt || new Date().toISOString();
          vulnNode.properties.fixExplanation = contradiction.resolutionNotes || 'Remediated via authoritative CTI vendor bulletin.';
          remediatedVulnIds.push(vulnNode.id);
          nodesAddedOrUpdated++;

          // Attach Mitigation node
          const patchId = `Patch for ${vulnNode.id}`;
          if (!graphState.nodes.some(n => n.id === patchId)) {
            graphState.nodes.push({
              id: patchId,
              properties: {
                label: 'Mitigation',
                name: patchId,
                description: contradiction.resolutionNotes || `CTI vendor patch applied for ${vulnNode.id}`,
                status: 'SELF_HEALED',
                timestamp: new Date().toISOString()
              }
            });
            nodesAddedOrUpdated++;
          }

          if (!graphState.edges.some(e => e.from === vulnNode.id && e.to === patchId && e.label === 'HAS_MITIGATION')) {
            graphState.edges.push({
              from: vulnNode.id,
              to: patchId,
              label: 'HAS_MITIGATION'
            });
            edgesAddedOrUpdated++;
          }
        }
      }
    }

    return {
      nodesAddedOrUpdated,
      edgesAddedOrUpdated,
      remediatedVulnIds,
      restoredHosts
    };
  }
}

export const ctiReconciler = new CTIReconciler();
