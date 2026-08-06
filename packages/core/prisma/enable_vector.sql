CREATE EXTENSION IF NOT EXISTS vector;

CREATE INDEX IF NOT EXISTS chunk_embedding_hnsw
  ON "RepositoryChunk"
  USING hnsw ("embeddingVec" vector_cosine_ops)
  WITH (m = 16, ef_construction = 64);

SELECT 'pgvector HNSW index ready' AS status;
