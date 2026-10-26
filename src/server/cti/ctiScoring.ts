import type { TemporalDecayConfig, TemporalStatus, SourceReliability } from './ctiTypes.ts';

export const DEFAULT_DECAY_CONFIG: TemporalDecayConfig = {
  enabled: true,
  halfLifeDays: 30,
  minimumWeight: 0.05,
  agingThresholdDays: 14,
  staleThresholdDays: 45,
  expiredThresholdDays: 90
};

export const SOURCE_RELIABILITY_MULTIPLIER: Record<SourceReliability, number> = {
  HIGH: 1.0,
  MEDIUM: 0.85,
  LOW: 0.65,
  UNKNOWN: 0.75
};

/**
 * Calculates temporal decay recency factor using exponential half-life decay.
 */
export function calculateRecencyFactor(
  lastObservedDate: string,
  now: Date = new Date(),
  config: TemporalDecayConfig = DEFAULT_DECAY_CONFIG
): number {
  if (!config.enabled) return 1.0;
  const observedTime = new Date(lastObservedDate).getTime();
  const currentTime = now.getTime();
  const ageMs = Math.max(0, currentTime - observedTime);
  const ageInDays = ageMs / (1000 * 60 * 60 * 24);

  // Half-life formula: 0.5 ^ (ageInDays / halfLifeDays)
  const factor = Math.pow(0.5, ageInDays / config.halfLifeDays);
  return Math.max(config.minimumWeight, Math.min(1.0, Number(factor.toFixed(4))));
}

/**
 * Evaluates the temporal status of an entity or relationship based on age and supersession.
 */
export function determineTemporalStatus(
  lastObservedDate: string,
  isSuperseded: boolean = false,
  now: Date = new Date(),
  config: TemporalDecayConfig = DEFAULT_DECAY_CONFIG
): TemporalStatus {
  if (isSuperseded) return 'SUPERSEDED';
  const observedTime = new Date(lastObservedDate).getTime();
  const currentTime = now.getTime();
  const ageMs = Math.max(0, currentTime - observedTime);
  const ageInDays = ageMs / (1000 * 60 * 60 * 24);

  if (ageInDays <= config.agingThresholdDays) return 'ACTIVE';
  if (ageInDays <= config.staleThresholdDays) return 'AGING';
  if (ageInDays <= config.expiredThresholdDays) return 'STALE';
  return 'EXPIRED';
}

/**
 * Computes dynamic evidence weight for a graph edge combining:
 * baseConfidence * recencyFactor * corroborationFactor * sourceReliability
 */
export function calculateEdgeWeight(params: {
  baseConfidence: number;
  lastObservedDate: string;
  corroborationCount: number;
  sourceReliability: SourceReliability;
  isSuperseded?: boolean;
  config?: TemporalDecayConfig;
  now?: Date;
}): {
  weight: number;
  recencyFactor: number;
  temporalStatus: TemporalStatus;
  corroborationFactor: number;
} {
  const cfg = params.config || DEFAULT_DECAY_CONFIG;
  const now = params.now || new Date();

  const recencyFactor = calculateRecencyFactor(params.lastObservedDate, now, cfg);
  const temporalStatus = determineTemporalStatus(params.lastObservedDate, params.isSuperseded, now, cfg);

  // Corroboration multiplier: 1.0 base, +0.15 for each additional independent document (up to 1.5x)
  const corroborationFactor = Math.min(1.5, 1.0 + Math.max(0, params.corroborationCount - 1) * 0.15);
  const reliabilityFactor = SOURCE_RELIABILITY_MULTIPLIER[params.sourceReliability] || 0.75;

  let rawWeight = params.baseConfidence * recencyFactor * corroborationFactor * reliabilityFactor;
  if (params.isSuperseded) {
    rawWeight *= 0.2; // Significantly dampened for superseded historical facts
  }

  const finalWeight = Math.max(cfg.minimumWeight, Math.min(1.0, Number(rawWeight.toFixed(3))));

  return {
    weight: finalWeight,
    recencyFactor,
    temporalStatus,
    corroborationFactor: Number(corroborationFactor.toFixed(2))
  };
}
