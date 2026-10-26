export type ThemeMode = 'dark' | 'light';

export interface GraphNode {
  id: string;
  name: string;
  label: 'ThreatActor' | 'Malware' | 'Technique' | 'Vulnerability' | 'Software' | 'Mitigation' | string;
  x: number;
  y: number;
  description?: string;
  details?: string;
  status?: 'HEALTHY' | 'COMPROMISED' | 'DEGRADED' | 'INITIALIZING' | 'UNMITIGATED' | 'SELF_HEALED' | 'APPROVED' | string;
  severity?: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | string;
  cvss?: number;
  cause?: string;
  reproduction?: string;
  installationProcedure?: string;
  symptoms?: string;
  troubleshootingProcess?: string;
  fixSolution?: string;
  verificationProcedure?: string;
  timestamp?: string;
  dataset?: string;
  injected_by?: string;
  ai_generated_description?: boolean;
  ai_generated_at?: string;
  resolved_at?: string;
  // Bug Code specific properties
  codeLanguage?: string;
  codeFileName?: string;
  buggyCode?: string;
  correctedCode?: string;
  errorMessage?: string;
  rootCause?: string;
  fixExplanation?: string;
  exploitScript?: string;
  // Computer / System specific properties
  hostname?: string;
  application?: string;
  technology?: string;
  cpu?: string;
  ram?: string;
  storage?: string;
  installedSoftware?: string;
  softwareVersions?: string;
  affectedComponent?: string;
  threat?: string;
  purpose?: string;
  environment?: string;
  os?: string;
  version?: string;
  port?: number;
  ip?: string;
  service?: string;
  configFile?: string;
  configPath?: string;
  availableTools?: string;
  dependencies?: string;
}

export interface GraphEdge {
  from: string;
  to: string;
  label: 'USES' | 'EXPLOITS' | 'AFFECTS' | 'HAS_MITIGATION' | string;
}

export interface SystemConfigData {
  id: string;
  name: string;
  hostname?: string;
  application?: string;
  technology?: string;
  cpu?: string;
  ram?: string;
  storage?: string;
  installedSoftware?: string;
  softwareVersions?: string;
  purpose: string;
  environment: string;
  os: string;
  version: string;
  port: number;
  ip: string;
  service: string;
  configFile: string;
  configPath: string;
  status: 'HEALTHY' | 'COMPROMISED' | 'DEGRADED' | 'INITIALIZING' | string;
  availableTools: string;
  dependencies: string;
  envVars?: Record<string, string>;
}

export interface BugDocumentation {
  id: string;
  name: string;
  targetSoftwareId: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  cvss: number;
  description: string;
  cause: string;
  reproduction: string;
  installationProcedure: string;
  symptoms: string;
  troubleshootingProcess: string;
  fixSolution: string;
  verificationProcedure: string;
  status: 'UNMITIGATED' | 'SELF_HEALED' | 'CLEAN';
  dataset: string;
  codeLanguage?: string;
  codeFileName?: string;
  buggyCode?: string;
  correctedCode?: string;
  errorMessage?: string;
  rootCause?: string;
  fixExplanation?: string;
  exploitScript?: string;
}

export type ProcessStage =
  | 'IDLE'
  | 'CREATING_SYSTEM'
  | 'INITIALIZING_SYSTEM'
  | 'SYSTEM_ACTIVE'
  | 'REMOVING_SYSTEM'
  | 'SYSTEM_REMOVED'
  | 'INSTALLING_BUG'
  | 'BUG_IN_PROGRESS'
  | 'BUG_INSTALLED'
  | 'BUG_DETECTED'
  | 'DIAGNOSING'
  | 'ANALYZING'
  | 'SOLUTION_IDENTIFIED'
  | 'FIXING'
  | 'FIX_APPLIED'
  | 'VERIFYING'
  | 'HEALTHY_RESTORED'
  | 'CONFIGURING'
  | 'CONFIG_APPLIED';

export interface ProcessAnimationState {
  stage: ProcessStage;
  active: boolean;
  title: string;
  subtitle: string;
  progress: number;
  targetId: string;
  logs: string[];
}
