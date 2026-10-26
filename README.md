# Self-Healing GraphRAG for Cross-Document Cybersecurity Threat Intelligence (CTI)

A production-grade cybersecurity threat intelligence platform featuring real-time multi-hop GraphRAG reasoning, multi-source CTI document ingestion, cross-document correlation, temporal decay scoring, conflict reconciliation, and autonomous vulnerability generation and self-healing.

---

## 1. System Architecture

```text
                  CTI SOURCES (Advisories, STIX 2.1, Reports, CVE Feeds)
                                            │
                                            ▼
                                MULTI-SOURCE CTI INGESTION
                                            │
                             ┌──────────────┴──────────────┐
                             ▼                             ▼
                  DOCUMENT CHUNKING              ENTITY EXTRACTION
                             │                             │
                             ▼                             ▼
                    VECTOR / HYBRID STORE            MITRE ALIGNMENT
                 (Semantic Similarity Index)               │
                             │                             ▼
                             │                    NEO4J KNOWLEDGE GRAPH
                             │                     (Nodes, Edges, Hops)
                             │                             │
                             └──────────────┬──────────────┘
                                            ▼
                                    GRAPHRAG ENGINE
                     (Multi-hop Traversal + Vector Evidence Retrieval)
                                            │
                                            ▼
                                    CONTEXT ASSEMBLY
                                            │
                                            ▼
                                    GEMINI 3.8 FLASH
                        (Threat Reasoning & Code Synthesis)
                                            │
                             ┌──────────────┴──────────────┐
                             ▼                             ▼
                    SAFE VULNERABLE CODE          SECURE REMEDIATION
                   (Isolated Simulation)          (Defensive Patches)
                             │                             │
                             └──────────────┬──────────────┘
                                            ▼
                              AUTOMATED VERIFICATION SUITE
                       (Static AST + Socket Simulation + Daemon Audit)
                                            │
                                            ▼
                                SELF-HEALING & MUTATION
                          (Mitigation Nodes + Graph State Sync)
```

---

## 2. Core Capabilities

### A. GraphRAG Retrieval & Deep Threat Reasoning
Unlike superficial LLM calls, the platform executes genuine GraphRAG:
1. **Multi-Hop Traversal:** Traverses live graph relationships (`AFFECTS`, `EXPLOITS`, `USES`, `TARGETS`, `RUNS_ON`, `MITIGATED_BY`, `HAS_MITIGATION`) across up to 3 hops from target assets.
2. **Semantic Vector Retrieval:** Searches chunked CTI intelligence documents using hybrid TF-IDF, token frequencies, and semantic vector similarity.
3. **Evidence Ranking & Temporal Weighting:** Evaluates source reliability (`HIGH`, `MEDIUM`, `LOW`), corroboration frequency across independent reports, and exponential temporal decay ($W = W_0 \times 2^{-\Delta t / t_{1/2}}$).
4. **MITRE ATT&CK & CWE Alignment:** Maps weaknesses to tactics, techniques (e.g. `T1059.004 Unix Shell`), and CWE classifications (e.g. `CWE-78 Command Injection`).
5. **Auditable Citations:** Provides explicit citations to graph nodes, edges, CTI document IDs, and confidence scores.

### B. Autonomous Vulnerability Solving & Verification Pipeline (15 Steps)
Users specify an asset, application, technology stack, and security flaw (e.g., `Computer 26`, `Payment Gateway`, `Node.js / Express`, `Command Injection`, `CRITICAL`):
- **Step 1:** Create or update affected System Node in the topology.
- **Step 2:** Instantiate the Vulnerability vector node.
- **Steps 3–7:** Retrieve graph knowledge, traverse multi-hop paths, query vector store for CTI evidence, and assemble ranked context.
- **Steps 8–12:** Reason over context with Gemini 3.8 Flash, synthesize safe isolated vulnerable code, analyze root causes, formulate remediation strategies, and generate clean secure code.
- **Step 13:** Mutate graph database by attaching Mitigation nodes and `HAS_MITIGATION` relationships.
- **Step 14:** Execute automated verification suite (Static AST checks, socket exploit payload simulation, daemon integrity audit, graph topology verification).
- **Step 15:** Recalculate security posture and update health state (`GENERATED` $\to$ `ANALYZED` $\to$ `PATCHED` $\to$ `VERIFIED` $\to$ `HEALTHY`).

### C. Cross-Document CTI Ingestion & Conflict Reconciliation
- **Ingestion Pipeline:** Ingests raw text, threat bulletins, and STIX feeds into canonical entities and relationships.
- **Conflict Detection:** Identifies contradictory intelligence across documents (e.g., positive vs. negative claims about adversary malware deployment) and marks them for review or automated resolution.
- **Temporal Self-Healing:** Configurable half-life decay engine distinguishing `ACTIVE`, `AGING`, `STALE`, and `EXPIRED` threat intelligence.

---

## 3. Technology Stack

- **Backend Runtime:** Node.js (v20+), TypeScript (`tsx`), Express
- **Graph Database:** Neo4j (Bolt driver `neo4j-driver`) with automatic high-performance local graph fallback
- **Vector / Retrieval Engine:** Semantic vector store with hybrid TF-IDF and n-gram lexical scoring
- **AI / LLM Engine:** Google Gemini 3.8 Flash (`@google/genai` TypeScript SDK)
- **Frontend Framework:** React 19, TypeScript, Vite 6, Tailwind CSS
- **Visualization:** Interactive SVG Graph Canvas with force-directed physics simulation and multi-layout modes (Pipeline, Zones, Rack, Organic)

---

## 4. Environment Variables

Create or update `.env` based on `.env.example`:

```bash
# Gemini AI API Key (Required for LLM reasoning; domain fallback active if absent)
GEMINI_API_KEY="your-gemini-api-key"

# Neo4j Graph Database Configuration (Optional; uses local high-performance storage if absent)
NEO4J_URI="bolt://localhost:7687"
NEO4J_USERNAME="neo4j"
NEO4J_PASSWORD="password123"

# Server Port
PORT=3000
```

---

## 5. API Reference

### GraphRAG & Vulnerability Workflow
- `POST /api/graphrag/vulnerability-workflow`: Execute the 15-step autonomous vulnerability generation, remediation, and verification pipeline.
- `POST /api/graphrag/query`: Deep multi-hop GraphRAG query with evidence citations and confidence scoring.
- `POST /api/graphrag/retrieve`: Inspect assembled GraphRAG context (nodes, edges, traversal paths, CTI evidence, MITRE mapping).

### CTI Ingestion & Reconciliation
- `POST /api/cti/ingest`: Ingest and parse a CTI report; extracts entities, relationships, detects contradictions, and indexes into vector store.
- `GET /api/cti/documents`: Retrieve all ingested CTI documents with metadata.
- `GET /api/cti/conflicts`: Retrieve active contradictions and resolution states.
- `GET /api/cti/timeline`: Ingestion and reconciliation audit events.
- `POST /api/cti/reconcile`: Trigger temporal decay recalculation and contradiction resolution pass.

### Graph & System Operations
- `GET /api/user/graph`: Retrieve live graph state (Software, Vulnerability, ThreatActor, Technique, Mitigation nodes).
- `GET /api/user/graph/report`: Download comprehensive JSON topology security posture report.
- `POST /api/user/chat`: GraphRAG Autonomous Copilot with deterministic fix commands (`fix`, `heal`, `fix <CVE>`).
- `POST /api/system/add` / `POST /api/system/remove` / `POST /api/system/configure`: Dynamic node lifecycle management.
- `POST /api/system/verify`: Live multi-check verification probe for software daemon and network integrity.

---

## 6. Running Locally

1. **Install dependencies:**
   ```bash
   npm install
   ```

2. **Start the development server:**
   ```bash
   npm run dev
   ```
   Open `http://localhost:3000` in your browser.

3. **Verify builds & types:**
   ```bash
   npm run lint
   npm run build
   ```

---

## 7. Safe Code Execution Policy

Generated vulnerable code is synthesized **strictly for controlled security analysis and educational demonstration**. The platform enforces safety boundaries:
- No execution of live malware, ransomware, or weaponized exploits.
- No access to real host secrets or external target infrastructure.
- Verification probes execute in controlled isolated simulation logic without damaging host integrity.
