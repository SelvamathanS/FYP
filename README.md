# Self-Healing GraphRAG CTI Web App

A production-ready full-stack cybersecurity threat intelligence platform. Built with Python FastAPI, Neo4j, Gemini Pro, and a React/Tailwind frontend.

## Features
- **Red Team Simulator (Hacker):** Dynamically inject zero-day `(:Vulnerability)` nodes affecting `(:Software)` assets into the Knowledge Graph.
- **WebSocket Broadcast:** Real-time push alerts to SOC Analyst dashboards upon vulnerability injection.
- **Neo4j Ontology Visualizer:** Interactive rendering of ThreatActors, Malware, Vulnerabilities, and Mitigations.
- **Self-Healing GraphRAG:** Analyzes Cypher attack paths. If an asset lacks a `[:HAS_MITIGATION]` edge, the Gemini Pro LangGraph reflection loop autonomously synthesizes a zero-day patch and writes the Mitigation node directly into the graph.

## Local Setup (Development)

1. **Install Dependencies**
   ```bash
   npm install
   pip install -r requirements.txt
   ```

2. **Configure Environment**
   Rename `.env.example` to `.env` and insert your Gemini API Key. (Neo4j and SQLite will use automatic fallbacks if omitted).

3. **Run Backend (FastAPI)**
   ```bash
   uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
   ```

4. **Run Frontend (Vite/React)**
   ```bash
   npm run dev
   ```

## Free Online Deployment Guide

You can host this entire stack for **$0/month** using cloud free tiers.

### 1. Neo4j Graph Database
- **Provider:** [Neo4j Aura (Free Tier)](https://neo4j.com/cloud/aura/)
- **Setup:** Create a free cluster. Note the Connection URI (`neo4j+s://...`), Username, and Password.
- **Action:** Add these to your `.env` as `NEO4J_URI`, `NEO4J_USERNAME`, and `NEO4J_PASSWORD`.

### 2. Gemini Pro LLM API
- **Provider:** [Google AI Studio](https://aistudio.google.com/)
- **Setup:** Generate a free API Key.
- **Action:** Add to `.env` as `GEMINI_API_KEY`.

### 3. Web App Hosting (FastAPI + React SPA)
- **Preparation:** Build the React frontend statically.
  ```bash
  npm run build
  ```
  *(The FastAPI `app/main.py` is configured to automatically serve the `/dist` folder statically).*
- **Provider:** [Render](https://render.com/) or [Railway](https://railway.app/)
- **Setup:**
  1. Connect your GitHub repository.
  2. Select "Docker" environment (or Python environment with start command `uvicorn app.main:app --host 0.0.0.0 --port $PORT`).
  3. Add the Environment Variables (NEO4J, GEMINI, etc.) in the dashboard.
  4. Deploy!
