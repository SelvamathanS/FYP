"""
Neo4j Graph Database Driver & CTI Knowledge Graph Engine.
Implements the ontology:
  (:ThreatActor)-[:USES]->(:Malware)-[:EXPLOITS]->(:Vulnerability)-[:AFFECTS]->(:Software)
  (:Vulnerability)-[:HAS_MITIGATION]->(:Mitigation)

Includes schema constraints, initial threat intel seeding, and resilient fallback execution.
"""

import os
import json
import logging
from typing import Dict, List, Any, Optional

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("graph_db")

# Neo4j connection configuration
NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USERNAME = os.getenv("NEO4J_USERNAME", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "password123")

# Try importing neo4j driver
try:
    from neo4j import GraphDatabase, exceptions as neo4j_exceptions
    HAS_NEO4J_PKG = True
except ImportError:
    HAS_NEO4J_PKG = False
    logger.warning("neo4j package not found in Python environment. Using high-fidelity in-memory graph engine.")


class InMemoryGraphStore:
    """
    High-fidelity in-memory graph fallback.
    Ensures tests and local execution pass immediately even before Neo4j Aura or local Docker is provisioned.
    Maintains exact node & relationship ontology for Vis.js and Self-Healing GraphRAG.
    """
    def __init__(self):
        self.nodes: Dict[str, Dict[str, Any]] = {}
        self.edges: List[Dict[str, Any]] = []

    def clear(self):
        self.nodes.clear()
        self.edges.clear()

    def add_node(self, node_id: str, label: str, properties: Dict[str, Any]):
        self.nodes[node_id] = {
            "id": node_id,
            "label": label,
            "name": properties.get("name", node_id),
            **properties
        }

    def add_edge(self, source_id: str, target_id: str, rel_type: str, properties: Optional[Dict[str, Any]] = None):
        # Prevent duplicate identical edges
        for edge in self.edges:
            if edge["source"] == source_id and edge["target"] == target_id and edge["type"] == rel_type:
                return
        self.edges.append({
            "source": source_id,
            "target": target_id,
            "type": rel_type,
            **(properties or {})
        })

    def get_snapshot(self) -> Dict[str, Any]:
        """Format nodes and edges for Vis.js network visualization."""
        color_map = {
            "ThreatActor": {"bg": "#ef4444", "border": "#b91c1c", "group": "threat_actor"}, # Red
            "Malware": {"bg": "#f97316", "border": "#c2410c", "group": "malware"},         # Orange
            "Vulnerability": {"bg": "#eab308", "border": "#a16207", "group": "vulnerability"}, # Amber/Yellow
            "Software": {"bg": "#3b82f6", "border": "#1d4ed8", "group": "software"},       # Blue
            "Mitigation": {"bg": "#10b981", "border": "#047857", "group": "mitigation"}     # Green
        }

        vis_nodes = []
        for n_id, data in self.nodes.items():
            label = data.get("label", "Node")
            style = color_map.get(label, {"bg": "#64748b", "border": "#334155", "group": "default"})
            vis_nodes.append({
                "id": n_id,
                "label": f"{data.get('name', n_id)}\n[{label}]",
                "title": f"<b>{data.get('name')}</b><br/>Type: {label}<br/>Details: {data.get('description', 'N/A')}",
                "group": style["group"],
                "color": {
                    "background": style["bg"],
                    "border": style["border"],
                    "highlight": {"background": "#ffffff", "border": style["border"]}
                },
                "shape": "dot",
                "size": 26 if label in ["ThreatActor", "Software"] else 20,
                "properties": data
            })

        vis_edges = []
        for idx, edge in enumerate(self.edges):
            vis_edges.append({
                "id": f"e_{idx}_{edge['source']}_{edge['target']}",
                "from": edge["source"],
                "to": edge["target"],
                "label": edge["type"],
                "arrows": "to",
                "font": {"size": 11, "align": "middle", "color": "#94a3b8"},
                "color": {"color": "#64748b", "highlight": "#38bdf8"}
            })

        return {"nodes": vis_nodes, "edges": vis_edges}


class Neo4jCTIManager:
    """
    Manages Neo4j connections, schema constraints, threat intelligence ontology,
    vulnerability injection, and graph traversal for the Self-Healing GraphRAG engine.
    """

    def __init__(self, uri: str = NEO4J_URI, user: str = NEO4J_USERNAME, password: str = NEO4J_PASSWORD):
        self.uri = uri
        self.user = user
        self.password = password
        self.driver = None
        self.fallback_store = InMemoryGraphStore()
        self.is_connected_to_neo4j = False

        self._connect()

    def _connect(self):
        """Attempt connection to Neo4j; fall back gracefully if unavailable."""
        if not HAS_NEO4J_PKG:
            self.is_connected_to_neo4j = False
            return

        try:
            self.driver = GraphDatabase.driver(self.uri, auth=(self.user, self.password))
            with self.driver.session() as session:
                session.run("RETURN 1 AS test")
            self.is_connected_to_neo4j = True
            logger.info("Successfully connected to Neo4j instance at %s", self.uri)
        except Exception as e:
            self.is_connected_to_neo4j = False
            logger.warning("Could not establish live Neo4j connection (%s). Operating in high-fidelity fallback mode.", e)

    def close(self):
        if self.driver:
            self.driver.close()

    def init_schema_constraints(self):
        """Create uniqueness constraints for the CTI ontology."""
        constraints = [
            "CREATE CONSTRAINT threat_actor_name IF NOT EXISTS FOR (t:ThreatActor) REQUIRE t.name IS UNIQUE",
            "CREATE CONSTRAINT malware_name IF NOT EXISTS FOR (m:Malware) REQUIRE m.name IS UNIQUE",
            "CREATE CONSTRAINT vulnerability_name IF NOT EXISTS FOR (v:Vulnerability) REQUIRE v.name IS UNIQUE",
            "CREATE CONSTRAINT software_name IF NOT EXISTS FOR (s:Software) REQUIRE s.name IS UNIQUE",
            "CREATE CONSTRAINT mitigation_name IF NOT EXISTS FOR (mi:Mitigation) REQUIRE mi.name IS UNIQUE"
        ]

        if self.is_connected_to_neo4j and self.driver:
            try:
                with self.driver.session() as session:
                    for cypher in constraints:
                        session.run(cypher)
                logger.info("Neo4j schema constraints successfully verified/created.")
            except Exception as e:
                logger.warning("Error creating constraints on Neo4j: %s", e)

    def seed_initial_data(self):
        """
        Seed initial domain dataset:
        - ThreatActor: APT29 (Cozy Bear)
        - Malware: WellMess
        - Vulnerability: CVE-2021-41773
        - Software: Apache Web Server
        - Mitigation: Patch Apache 2.4.51
        """
        # Always seed fallback store
        self.fallback_store.clear()
        self.fallback_store.add_node("APT29", "ThreatActor", {
            "name": "APT29",
            "aliases": "Cozy Bear, Nobelium",
            "origin": "Russia",
            "description": "Russian state-sponsored advanced persistent threat actor known for targeting government, diplomatic, and think-tank entities."
        })
        self.fallback_store.add_node("WellMess", "Malware", {
            "name": "WellMess",
            "type": "Remote Access Trojan (RAT)",
            "description": "Cross-platform Go/.NET malware capable of arbitrary command execution and file exfiltration over TLS."
        })
        self.fallback_store.add_node("CVE-2021-41773", "Vulnerability", {
            "name": "CVE-2021-41773",
            "severity": "CRITICAL (9.8)",
            "description": "Path traversal and remote code execution vulnerability in Apache HTTP Server 2.4.49."
        })
        self.fallback_store.add_node("Apache Web Server", "Software", {
            "name": "Apache Web Server",
            "version": "2.4.49",
            "asset_id": "SRV-PROD-WEB01",
            "description": "Core public-facing production web server hosting client portal."
        })
        self.fallback_store.add_node("Patch Apache 2.4.51", "Mitigation", {
            "name": "Patch Apache 2.4.51",
            "description": "Upgrade Apache HTTP Server to version 2.4.51 or later. Enforce 'Require all denied' in default directory configuration.",
            "status": "APPROVED",
            "provenance": "Vendor Advisory / CISA KEV"
        })

        # Seed relationships
        self.fallback_store.add_edge("APT29", "WellMess", "USES")
        self.fallback_store.add_edge("WellMess", "CVE-2021-41773", "EXPLOITS")
        self.fallback_store.add_edge("CVE-2021-41773", "Apache Web Server", "AFFECTS")
        self.fallback_store.add_edge("CVE-2021-41773", "Patch Apache 2.4.51", "HAS_MITIGATION")

        # Also add a target asset waiting for attack
        self.fallback_store.add_node("OpenSSL Engine", "Software", {
            "name": "OpenSSL Engine",
            "version": "1.1.1k",
            "asset_id": "SRV-CRYPTO-01",
            "description": "Core cryptographic library underpinning API gateway."
        })

        if self.is_connected_to_neo4j and self.driver:
            seed_cypher = """
            MERGE (t:ThreatActor {name: 'APT29'})
            SET t.origin = 'Russia', t.description = 'Cozy Bear state-sponsored espionage group'

            MERGE (m:Malware {name: 'WellMess'})
            SET m.type = 'RAT', m.description = 'Custom Go/TLS remote access Trojan'

            MERGE (v:Vulnerability {name: 'CVE-2021-41773'})
            SET v.severity = 'CRITICAL (9.8)', v.description = 'Apache 2.4.49 path traversal & RCE'

            MERGE (s:Software {name: 'Apache Web Server'})
            SET s.version = '2.4.49', s.asset_id = 'SRV-PROD-WEB01'

            MERGE (s2:Software {name: 'OpenSSL Engine'})
            SET s2.version = '1.1.1k', s2.asset_id = 'SRV-CRYPTO-01'

            MERGE (mi:Mitigation {name: 'Patch Apache 2.4.51'})
            SET mi.description = 'Upgrade to Apache HTTP Server 2.4.51+ and restrict root path access'

            MERGE (t)-[:USES]->(m)
            MERGE (m)-[:EXPLOITS]->(v)
            MERGE (v)-[:AFFECTS]->(s)
            MERGE (v)-[:HAS_MITIGATION]->(mi)
            """
            try:
                with self.driver.session() as session:
                    session.run(seed_cypher)
                logger.info("Successfully seeded initial CTI data in Neo4j.")
            except Exception as e:
                logger.warning("Failed to seed Neo4j: %s", e)

    def inject_vulnerability(self, vuln_name: str, target_software: str, description: str) -> Dict[str, Any]:
        """
        Red Team Action:
        Injects a new (:Vulnerability) node and links it to (:Software) via [:AFFECTS].
        Notice: The injected vulnerability deliberately lacks a [:HAS_MITIGATION] edge.
        This provides the target for the Self-Healing Reflection Loop!
        """
        # Update fallback store
        self.fallback_store.add_node(vuln_name, "Vulnerability", {
            "name": vuln_name,
            "description": description,
            "injected_by": "Hacker (Red Team)",
            "status": "UNMITIGATED",
            "injected_at": str(os.getenv("CURRENT_TIME", "Just Now"))
        })

        # Ensure target software exists
        if target_software not in self.fallback_store.nodes:
            self.fallback_store.add_node(target_software, "Software", {
                "name": target_software,
                "asset_id": f"SRV-{target_software.replace(' ', '-').upper()}",
                "description": f"Targeted enterprise asset: {target_software}"
            })

        self.fallback_store.add_edge(vuln_name, target_software, "AFFECTS")

        # In Neo4j
        if self.is_connected_to_neo4j and self.driver:
            cypher = """
            MERGE (v:Vulnerability {name: $vuln_name})
            SET v.description = $description,
                v.injected_by = 'Hacker (Red Team)',
                v.status = 'UNMITIGATED',
                v.created_at = timestamp()
            MERGE (s:Software {name: $target_software})
            MERGE (v)-[:AFFECTS]->(s)
            RETURN v, s
            """
            try:
                with self.driver.session() as session:
                    session.run(cypher, vuln_name=vuln_name, target_software=target_software, description=description)
            except Exception as e:
                logger.warning("Error injecting into Neo4j: %s", e)

        return {
            "vulnerability": vuln_name,
            "target_software": target_software,
            "description": description,
            "status": "INJECTED_UNMITIGATED",
            "missing_mitigation": True
        }

    def add_mitigation(self, vuln_name: str, mitigation_name: str, details: str, provenance: str = "Self-Healed via Gemini AI & CTI Feeds") -> Dict[str, Any]:
        """
        Self-Healing Action:
        Adds a (:Mitigation) node and connects (:Vulnerability)-[:HAS_MITIGATION]->(:Mitigation).
        Resolves the broken graph path.
        """
        self.fallback_store.add_node(mitigation_name, "Mitigation", {
            "name": mitigation_name,
            "description": details,
            "provenance": provenance,
            "status": "SELF_HEALED"
        })
        self.fallback_store.add_edge(vuln_name, mitigation_name, "HAS_MITIGATION")

        if vuln_name in self.fallback_store.nodes:
            self.fallback_store.nodes[vuln_name]["status"] = "MITIGATED"

        if self.is_connected_to_neo4j and self.driver:
            cypher = """
            MATCH (v:Vulnerability {name: $vuln_name})
            MERGE (mi:Mitigation {name: $mitigation_name})
            SET mi.description = $details,
                mi.provenance = $provenance,
                mi.status = 'SELF_HEALED',
                mi.healed_at = timestamp()
            SET v.status = 'MITIGATED'
            MERGE (v)-[:HAS_MITIGATION]->(mi)
            RETURN v, mi
            """
            try:
                with self.driver.session() as session:
                    session.run(cypher, vuln_name=vuln_name, mitigation_name=mitigation_name, details=details, provenance=provenance)
            except Exception as e:
                logger.warning("Error adding mitigation to Neo4j: %s", e)

        return {
            "vulnerability": vuln_name,
            "mitigation": mitigation_name,
            "details": details,
            "provenance": provenance,
            "status": "HEALED"
        }

    def get_graph_snapshot(self) -> Dict[str, Any]:
        """Retrieve full network graph for Vis.js visualization."""
        if self.is_connected_to_neo4j and self.driver:
            try:
                cypher = """
                MATCH (n)
                OPTIONAL MATCH (n)-[r]->(m)
                RETURN n, r, m
                """
                with self.driver.session() as session:
                    result = session.run(cypher)
                    nodes_map = {}
                    edges_list = []
                    for record in result:
                        n = record["n"]
                        if n:
                            n_label = list(n.labels)[0] if n.labels else "Node"
                            nodes_map[n.get("name", str(n.id))] = {
                                "id": n.get("name", str(n.id)),
                                "label": n_label,
                                "name": n.get("name", str(n.id)),
                                **dict(n)
                            }
                        m = record["m"]
                        r = record["r"]
                        if m and r:
                            m_label = list(m.labels)[0] if m.labels else "Node"
                            nodes_map[m.get("name", str(m.id))] = {
                                "id": m.get("name", str(m.id)),
                                "label": m_label,
                                "name": m.get("name", str(m.id)),
                                **dict(m)
                            }
                            edges_list.append({
                                "source": n.get("name", str(n.id)),
                                "target": m.get("name", str(m.id)),
                                "type": r.type,
                                **dict(r)
                            })

                    temp_store = InMemoryGraphStore()
                    for n_id, n_data in nodes_map.items():
                        temp_store.add_node(n_id, n_data["label"], n_data)
                    for e in edges_list:
                        temp_store.add_edge(e["source"], e["target"], e["type"], e)
                    return temp_store.get_snapshot()
            except Exception as e:
                logger.warning("Error querying Neo4j snapshot: %s. Falling back to local store.", e)

        return self.fallback_store.get_snapshot()

    def find_vulnerability_with_lineage(self, vuln_or_software_keyword: str) -> Dict[str, Any]:
        """
        Traverse the graph to discover:
        ThreatActor -> Malware -> Vulnerability -> Software -> Mitigation.
        Detects if there is a hole (missing mitigation) on an affected asset.
        """
        snapshot = self.get_graph_snapshot()
        keyword_lower = vuln_or_software_keyword.lower()

        # Find matching vulnerability or affected software
        target_vulns = []
        for node in snapshot["nodes"]:
            props = node.get("properties", {})
            name = props.get("name", "").lower()
            if props.get("label") == "Vulnerability" and (keyword_lower in name or keyword_lower in props.get("description", "").lower()):
                target_vulns.append(node["id"])

        # If not found directly, check software name
        if not target_vulns:
            for node in snapshot["nodes"]:
                props = node.get("properties", {})
                if props.get("label") == "Software" and keyword_lower in props.get("name", "").lower():
                    # Find incoming AFFECTS edges
                    for edge in snapshot["edges"]:
                        if edge["to"] == node["id"] and edge["label"] == "AFFECTS":
                            target_vulns.append(edge["from"])

        results = []
        for vuln_id in target_vulns:
            vuln_node = next((n for n in snapshot["nodes"] if n["id"] == vuln_id), None)
            affected_software = [e["to"] for e in snapshot["edges"] if e["from"] == vuln_id and e["label"] == "AFFECTS"]
            mitigations = [e["to"] for e in snapshot["edges"] if e["from"] == vuln_id and e["label"] == "HAS_MITIGATION"]
            exploiting_malware = [e["from"] for e in snapshot["edges"] if e["to"] == vuln_id and e["label"] == "EXPLOITS"]

            threat_actors = []
            for m in exploiting_malware:
                threat_actors.extend([e["from"] for e in snapshot["edges"] if e["to"] == m and e["label"] == "USES"])

            results.append({
                "vulnerability": vuln_id,
                "vuln_properties": vuln_node.get("properties", {}) if vuln_node else {},
                "affected_software": affected_software,
                "exploiting_malware": exploiting_malware,
                "threat_actors": list(set(threat_actors)),
                "mitigations": mitigations,
                "is_healed": len(mitigations) > 0,
                "has_hole": len(mitigations) == 0
            })

        return {
            "query": vuln_or_software_keyword,
            "matches": results,
            "total_nodes": len(snapshot["nodes"]),
            "total_edges": len(snapshot["edges"])
        }


# Global singleton instance
graph_db = Neo4jCTIManager()
graph_db.init_schema_constraints()
graph_db.seed_initial_data()
