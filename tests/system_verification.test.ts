/**
 * Autonomous Self-Healing GraphRAG CTI Platform
 * Comprehensive Verification & Production Readiness Test Suite
 */

import fs from 'fs';
import path from 'path';
import { ctiReconciler } from '../src/server/cti/ctiReconciler.ts';
import { vectorStore } from '../src/server/graphrag/vectorStore.ts';
import { vulnerabilityPipeline } from '../src/server/graphrag/vulnerabilityPipeline.ts';
import { DEFAULT_GRAPH_DATA } from '../src/data/defaultGraph.ts';

function assert(condition: boolean, message: string) {
  if (!condition) {
    console.error(`❌ ASSERTION FAILED: ${message}`);
    throw new Error(message);
  }
  console.log(`  ✓ ${message}`);
}

async function runTestSuite() {
  console.log('\n======================================================');
  console.log('🧪 RUNNING PRODUCTION READINESS TEST SUITE');
  console.log('======================================================\n');

  let passedTests = 0;
  let totalTests = 0;

  // ---------------------------------------------------------
  // TEST 1: Enterprise Topology & Computer 26 Clean Baseline
  // ---------------------------------------------------------
  totalTests++;
  console.log('--- TEST 1: Enterprise Topology & Computer 26 Baseline ---');
  {
    const stateFile = path.join(process.cwd(), 'data/graph_state.json');
    assert(fs.existsSync(stateFile), 'data/graph_state.json exists on disk');
    const state = JSON.parse(fs.readFileSync(stateFile, 'utf8'));

    const softwareNodes = state.nodes.filter((n: any) => 
      n.properties?.label === 'Software' && (n.id.startsWith('Computer ') || n.properties?.name?.startsWith('Computer '))
    );
    assert(softwareNodes.length === 28, `All 28 enterprise software hosts are present (found ${softwareNodes.length})`);

    const comp26 = state.nodes.find((n: any) => n.id === 'Computer 26');
    assert(!!comp26, 'Computer 26 host node exists');
    assert(comp26.properties.status === 'HEALTHY', `Computer 26 baseline status is HEALTHY (found ${comp26.properties.status})`);
    assert(comp26.properties.vulnerabilityStatus === 'NONE', 'Computer 26 vulnerability status is NONE');

    const vulnPay = state.nodes.find((n: any) => n.id === 'VULN-PAY-001');
    assert(!vulnPay, 'Computer 26 does NOT start already healed or compromised (no VULN-PAY-001 in baseline)');

    // Verify canonical enterprise vulnerabilities exist
    const canonVulns = ['CVE-2023-39417', 'CVE-2021-44228', 'CVE-2023-30861'];
    for (const cv of canonVulns) {
      const vNode = state.nodes.find((n: any) => n.id === cv);
      assert(!!vNode, `Canonical enterprise vulnerability ${cv} exists`);
    }
  }
  passedTests++;
  console.log('✅ TEST 1 PASSED: Enterprise Topology Baseline verified.\n');

  // ---------------------------------------------------------
  // TEST 2: CTI Sentence-Level Claim Extraction (No False Combinations)
  // ---------------------------------------------------------
  totalTests++;
  console.log('--- TEST 2: CTI Sentence-Level Claim Extraction ---');
  {
    const rawReport = `
      Advanced Persistent Threat group APT29 used technique T1059 for command execution in recent campaigns.
      A distinct zero-day disclosure discusses CVE-2023-9999 affecting obsolete unmonitored devices.
      Computer 07 telemetry recorded standard periodic backup completion at 04:00 UTC.
    `;

    const ingestResult = ctiReconciler.ingestDocumentInternal(rawReport, {
      documentId: 'TEST-CTI-DISJOINT',
      title: 'Disjoint Multi-Sentence Threat Advisory',
      sourceReliability: 'HIGH'
    });

    const relations = ctiReconciler.getRelationships().filter(r => r.sourceDocumentIds.includes('TEST-CTI-DISJOINT'));

    // Should extract APT29 -> USES -> T1059 because they appear in the same sentence with action verb
    const aptUsesTech = relations.find(r => r.sourceId === 'APT29' && r.targetId === 'T1059' && r.relationshipType === 'USES');
    assert(!!aptUsesTech, 'Correctly extracted claim: APT29 USES T1059 from sentence 1');

    // MUST NOT create false cross-product relationships across sentences
    const falseAptVuln = relations.find(r => r.sourceId === 'APT29' && r.targetId === 'CVE-2023-9999');
    assert(!falseAptVuln, 'Prevented false combination: APT29 -> CVE-2023-9999 (appeared in different sentences)');

    const falseVulnComp = relations.find(r => r.sourceId === 'CVE-2023-9999' && r.targetId === 'Computer 07');
    assert(!falseVulnComp, 'Prevented false combination: CVE-2023-9999 -> Computer 07 (appeared in different sentences)');
  }
  passedTests++;
  console.log('✅ TEST 2 PASSED: Sentence-level claim extraction avoids false combinations.\n');

  // ---------------------------------------------------------
  // TEST 3: CTI Temporal Decay & Live Edge Property Sync
  // ---------------------------------------------------------
  totalTests++;
  console.log('--- TEST 3: Temporal Decay & Edge Property Synchronization ---');
  {
    // Update decay config to fast decay for testing
    ctiReconciler.updateDecayConfig({ halfLifeDays: 5 });
    ctiReconciler.recalculateAllWeights();

    const relationships = ctiReconciler.getRelationships();
    assert(relationships.length > 0, 'CTI relationships exist');

    const sampleRel = relationships[0];
    assert(typeof sampleRel.currentWeight === 'number' && sampleRel.currentWeight > 0, 'Calculated numeric dynamic weight');
    assert(typeof sampleRel.recencyFactor === 'number', 'Calculated temporal recency factor');
    assert(['ACTIVE', 'AGING', 'STALE', 'EXPIRED', 'SUPERSEDED'].includes(sampleRel.temporalStatus), `Assigned valid temporal status (${sampleRel.temporalStatus})`);

    // Test syncWithGraphState updates existing edges
    const mockGraph = {
      nodes: [
        { id: sampleRel.sourceId, properties: { label: 'ThreatActor' } },
        { id: sampleRel.targetId, properties: { label: 'Technique' } }
      ],
      edges: [
        {
          from: sampleRel.sourceId,
          to: sampleRel.targetId,
          label: sampleRel.relationshipType,
          weight: 0.1, // outdated initial weight
          temporalStatus: 'STALE'
        }
      ]
    };

    const syncResult = ctiReconciler.syncWithGraphState(mockGraph);
    const syncedEdge: any = mockGraph.edges[0];
    assert(syncedEdge.weight === sampleRel.currentWeight, 'Live graph edge weight synchronized with CTI layer');
    assert(syncedEdge.temporalStatus === sampleRel.temporalStatus, 'Live graph edge temporal status synchronized');
    assert(syncedEdge.properties?.weight === sampleRel.currentWeight, 'Edge.properties.weight also synchronized');
  }
  passedTests++;
  console.log('✅ TEST 3 PASSED: Temporal decay and edge property sync verified.\n');

  // ---------------------------------------------------------
  // TEST 4: Semantic Vector Store & Persistent Disk Index
  // ---------------------------------------------------------
  totalTests++;
  console.log('--- TEST 4: Vector Store & Persistent Disk Index ---');
  {
    const chunkCountBefore = vectorStore.getChunkCount();
    assert(chunkCountBefore > 0, `Vector store initialized with knowledge base (${chunkCountBefore} chunks)`);

    const testVec1 = vectorStore.generateDenseEmbedding('Node.js command injection execFile sanitization');
    const testVec2 = vectorStore.generateDenseEmbedding('Node.js remote code execution child process vulnerability');
    const testVec3 = vectorStore.generateDenseEmbedding('PostgreSQL database relational table schema index query');

    assert(testVec1.length === 64, 'Dense vector embedding has 64 dimensions');

    const cosSimRel = vectorStore.calculateCosineSimilarity(testVec1, testVec2);
    const cosSimUnrel = vectorStore.calculateCosineSimilarity(testVec1, testVec3);

    assert(cosSimRel > cosSimUnrel, `Semantic similarity between related topics (${cosSimRel.toFixed(3)}) is higher than unrelated (${cosSimUnrel.toFixed(3)})`);

    // Verify index persistence to disk
    vectorStore.saveToDisk();
    const vectorIndexFile = path.join(process.cwd(), 'data/vector_index.json');
    assert(fs.existsSync(vectorIndexFile), 'data/vector_index.json persisted to disk');
    const parsedIndex = JSON.parse(fs.readFileSync(vectorIndexFile, 'utf8'));
    assert(Array.isArray(parsedIndex.chunks) && parsedIndex.chunks.length > 0, 'Vector store index contains serialized chunks');
  }
  passedTests++;
  console.log('✅ TEST 4 PASSED: Vector store semantic similarity and persistence verified.\n');

  // ---------------------------------------------------------
  // TEST 5: Computer 26 Complete Self-Healing Lifecycle
  // ---------------------------------------------------------
  totalTests++;
  console.log('--- TEST 5: Computer 26 Complete Self-Healing Lifecycle ---');
  {
    const testGraphState = JSON.parse(JSON.stringify(DEFAULT_GRAPH_DATA));

    // Phase 1: Baseline inspection
    const c26 = testGraphState.nodes.find((n: any) => n.id === 'Computer 26');
    assert(c26.properties.status === 'HEALTHY', 'Phase 1: Computer 26 starts HEALTHY');

    // Phase 2: Inject Bug (VULN-PAY-001)
    const vulnId = 'VULN-PAY-001';
    testGraphState.nodes.push({
      id: vulnId,
      properties: {
        label: 'Vulnerability',
        name: 'Payment Gateway Command Injection',
        status: 'UNMITIGATED',
        severity: 'CRITICAL',
        cvss: 9.8,
        cwe: 'CWE-78',
        cause: 'Unsanitized parameter inputs passed to child process execution routines'
      }
    });
    testGraphState.edges.push({
      from: vulnId,
      to: 'Computer 26',
      label: 'AFFECTS'
    });
    c26.properties.status = 'COMPROMISED';
    assert(c26.properties.status === 'COMPROMISED', 'Phase 2: Computer 26 transitioned to COMPROMISED');

    // Phase 3: Autonomous Remediation & 4-Tier Verification
    const workflowResult = await vulnerabilityPipeline.execute({
      system: 'Computer 26',
      application: 'Payment Gateway',
      technology: 'Node.js / Express',
      bug: 'Command Injection',
      severity: 'CRITICAL',
      autoRemediateAndVerify: true
    }, testGraphState);

    assert(workflowResult.status === 'VERIFIED', 'Phase 3: 4-tier independent verification PASSED');
    assert(workflowResult.verificationChecks.length === 4, 'All 4 verification checks executed');
    for (const check of workflowResult.verificationChecks) {
      assert(check.status === 'PASS', `Check '${check.name}' PASSED: ${check.detail}`);
    }

    // Phase 4: State transition verification
    const vulnNode = testGraphState.nodes.find((n: any) => n.id === vulnId);
    assert(vulnNode.properties.status === 'SELF_HEALED', 'Phase 4: Vulnerability node transitioned to SELF_HEALED');

    const mitigationNode = testGraphState.nodes.find((n: any) => n.id === 'Payment Gateway Mitigation');
    assert(!!mitigationNode && mitigationNode.properties.status === 'VERIFIED', 'Mitigation node created with VERIFIED status');

    const comp26Post = testGraphState.nodes.find((n: any) => n.id === 'Computer 26');
    assert(comp26Post.properties.status === 'HEALTHY', 'Computer 26 host restored to HEALTHY');
  }
  passedTests++;
  console.log('✅ TEST 5 PASSED: Computer 26 Autonomous Self-Healing Lifecycle verified.\n');

  console.log('======================================================');
  console.log(`🎉 ALL ${passedTests}/${totalTests} TESTS PASSED SUCCESSFULLY!`);
  console.log('======================================================\n');
}

runTestSuite().catch(err => {
  console.error('\n❌ TEST SUITE FAILURE:', err);
  process.exit(1);
});
