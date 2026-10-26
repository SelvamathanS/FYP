import type { CTIDocument } from './ctiTypes.ts';

// Dates relative to current runtime for realistic temporal progression
const now = Date.now();
const dayMs = 24 * 60 * 60 * 1000;

export const SYNTHETIC_CTI_REPORTS: CTIDocument[] = [
  {
    documentId: 'CTI-DOC-001',
    title: 'SYNTHETIC: APT29 Initial Infrastructure Incursion & PostgreSQL Exploitation',
    source: 'National Cyber Security Advisory Feed (Synthetic)',
    sourceType: 'REPORT',
    publishedAt: new Date(now - 48 * dayMs).toISOString(),
    observedAt: new Date(now - 50 * dayMs).toISOString(),
    ingestedAt: new Date(now - 47 * dayMs).toISOString(),
    lastSeenAt: new Date(now - 45 * dayMs).toISOString(),
    confidence: 0.92,
    sourceReliability: 'HIGH',
    classification: 'INTERNAL',
    contentHash: 'a1b2c3d4e5f67890123456789abcdef012345678',
    status: 'ACTIVE',
    rawText: `[SYNTHETIC THREAT INTELLIGENCE ADVISORY - NOT A REAL EXPLOIT]
Threat Actor: APT29 (also tracked as Cozy Bear, Midnight Blizzard)
Campaign: Strategic Corporate Database Reconnaissance
Technique: T1190 (Exploit Public-Facing Application)
Vulnerability: CVE-2023-39417 (PostgreSQL SQL Injection & Dynamic Execution)
Target System: Computer 07 (Customer Database, running PostgreSQL on port 5432)

Summary:
Intelligence indicators confirm threat actor APT29 has actively utilized technique T1190 to exploit public-facing PostgreSQL interfaces. Incursion traces identify targeted SQL parameter tampering affecting Computer 07. The adversary bypasses input validation using dynamic SQL concatenation.`
  },
  {
    documentId: 'CTI-DOC-002',
    title: 'SYNTHETIC: Cross-Campaign Lateral Movement & Java Log4j Exploitation',
    source: 'Commercial SOC Incident Response Dispatch (Synthetic)',
    sourceType: 'INCIDENT',
    publishedAt: new Date(now - 14 * dayMs).toISOString(),
    observedAt: new Date(now - 15 * dayMs).toISOString(),
    ingestedAt: new Date(now - 13 * dayMs).toISOString(),
    lastSeenAt: new Date(now - 10 * dayMs).toISOString(),
    confidence: 0.88,
    sourceReliability: 'HIGH',
    classification: 'RESTRICTED',
    contentHash: 'b2c3d4e5f67890123456789abcdef0123456789a',
    status: 'ACTIVE',
    rawText: `[SYNTHETIC THREAT INTELLIGENCE INCIDENT REPORT - NOT A REAL EXPLOIT]
Threat Actor: APT29 (Cozy Bear) and FIN7 Syndicate
Techniques: T1190 (Exploit Public-Facing Application), T1059 (Command and Scripting Interpreter)
Vulnerabilities: CVE-2021-44228 (Log4Shell / Spring Boot JNDI RCE)
Target Systems: Computer 14 (Employee Management, Java Spring Boot port 8080) and Computer 07

Summary:
Telemetry corroborates APT29 continuing exploitation of public-facing endpoints via T1190. Additionally, the group leverages command interpreter T1059 to trigger remote JNDI lookups via Log4Shell (CVE-2021-44228) against Computer 14. 
Claim: Host Computer 14 remains vulnerable and unmitigated.`
  },
  {
    documentId: 'CTI-DOC-003',
    title: 'SYNTHETIC: Authoritative Security Patch Advisory & Mitigation Reconciliation',
    source: 'Vendor Emergency Security Bulletin & SRE Verification (Synthetic)',
    sourceType: 'ADVISORY',
    publishedAt: new Date(now - 1 * dayMs).toISOString(),
    observedAt: new Date(now - 1 * dayMs).toISOString(),
    ingestedAt: new Date(now).toISOString(),
    lastSeenAt: new Date(now).toISOString(),
    confidence: 0.98,
    sourceReliability: 'HIGH',
    classification: 'PUBLIC',
    contentHash: 'c3d4e5f67890123456789abcdef0123456789ab1',
    status: 'ACTIVE',
    rawText: `[SYNTHETIC VENDOR SECURITY ADVISORY & MITIGATION BULLETIN]
Vulnerability: CVE-2021-44228 (Log4Shell)
Mitigation: Mitigation-Java-14 (Autonomous JNDI Lookup Lockdown & Spring Security Patch)
Target System: Computer 14 (Employee Management)

Summary & Contradiction Resolution:
Official vendor advisory verifies that Computer 14 has enforced complete JNDI lookup disabling and log4j-core 2.17.1 security patches. 
Contradiction Claim: Prior reports asserting Computer 14 is unmitigated are now SUPERSEDED. Host Computer 14 is fully patched, verified healthy, and immune to CVE-2021-44228.`
  }
];
