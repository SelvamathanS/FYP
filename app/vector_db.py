import logging
import os

logger = logging.getLogger("vector_db")

try:
    import chromadb
    HAS_CHROMA = True
except ImportError:
    HAS_CHROMA = False
    logger.warning("chromadb package not found. Using mocked Vector DB fallback.")

class VectorDBManager:
    """
    Manages ChromaDB vector store for unstructured chunks and semantic embeddings.
    Provides fallback mechanisms for smooth local execution.
    """
    def __init__(self):
        self.collection = None
        self.is_connected = False
        self.mock_store = []
        
        if HAS_CHROMA:
            chroma_key = os.getenv("CHROMA_API_KEY")
            chroma_tenant = os.getenv("CHROMA_TENANT", "default_tenant")
            chroma_database = os.getenv("CHROMA_DATABASE", "default_database")
            if chroma_key:
                try:
                    self.client = chromadb.CloudClient(
                        api_key=chroma_key,
                        tenant=chroma_tenant,
                        database=chroma_database
                    )
                    self.collection = self.client.get_or_create_collection(name="cti_reports")
                    self.is_connected = True
                    self._seed_initial_data()
                    logger.info("ChromaDB Cloud initialized and seeded.")
                except Exception as e:
                    logger.error(f"Failed to init ChromaDB Cloud: {e}")
                    self._seed_initial_data()
            else:
                self._seed_initial_data()
        else:
            self._seed_initial_data()

    def _seed_initial_data(self):
        reports = [
            {"id": "doc1", "text": "APT29 has been observed using WellMess RAT to target enterprise environments and exfiltrate data.", "meta": {"source": "CISA Alert"}},
            {"id": "doc2", "text": "CVE-2021-41773 allows path traversal in Apache Web Server, leading to remote code execution. Mitigation involves upgrading to 2.4.51.", "meta": {"source": "NVD Feed"}}
        ]
        for r in reports:
            self.add_report(r["id"], r["text"], r["meta"])

    def add_report(self, doc_id: str, text: str, metadata: dict):
        """Indexes an unstructured threat report text into the vector store."""
        if self.is_connected and self.collection:
            try:
                self.collection.add(documents=[text], metadatas=[metadata], ids=[doc_id])
            except Exception as e:
                logger.warning(f"Error indexing to Chroma: {e}")
        else:
            self.mock_store.append({"id": doc_id, "text": text, "metadata": metadata})

    def search(self, query: str, n_results: int = 2) -> list:
        """Performs dense vector similarity search."""
        if self.is_connected and self.collection:
            try:
                results = self.collection.query(query_texts=[query], n_results=n_results)
                docs = results.get("documents", [[]])[0]
                metas = results.get("metadatas", [[]])[0]
                return [{"text": d, "metadata": m} for d, m in zip(docs, metas)]
            except Exception as e:
                logger.error(f"Chroma search error: {e}")
                return []
        else:
            # Naive fallback semantic search via keyword matching
            query_words = query.lower().split()
            res = [d for d in self.mock_store if any(word in d["text"].lower() for word in query_words)]
            return res[:n_results]

vector_db = VectorDBManager()
