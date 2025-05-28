import numpy as np
from langchain_community.vectorstores import Chroma
from langchain_openai import OpenAIEmbeddings
import tiktoken
import logging
class CodeVectorDatabase:
    COLLECTION_NAME = "code_documents"

    def __init__(self, embedding_model=None, persist_directory="./code_db"):
        self.logger = logging.getLogger(__name__)
        self.embedding_model = embedding_model or OpenAIEmbeddings(chunk_size=256)
        self.persist_directory = persist_directory
        self.vector_db = None
        try:
            self.tokenizer = tiktoken.encoding_for_model("text-embedding-ada-002")
        except KeyError:
            self.tokenizer = tiktoken.get_encoding("cl100k_base")
        
    def _get_tokens(self, text: str) -> int:
        """Helper function to count tokens in a text string."""
        return len(self.tokenizer.encode(text))

    def index_code_chunks(self, code_chunks):
        """Index code chunks for semantic search with dynamic batching based on token counts."""
        MAX_TOKENS_PER_API_BATCH = 250000

        if not code_chunks:
            return 0

        current_batch_docs = []
        current_batch_tokens = 0
        total_indexed_count = 0

        for i, doc in enumerate(code_chunks):
            doc_content = doc.page_content
            try:
                doc_tokens = self._get_tokens(doc_content)
            except Exception as e:
                source_info = "Unknown source"
                if hasattr(doc, 'metadata') and isinstance(doc.metadata, dict):
                    source_info = doc.metadata.get('source', 'N/A')
                self.logger.debug(f"Warning: Could not tokenize document from {source_info} (index {i}): {e}. Skipping.")
                continue

            if doc_tokens > MAX_TOKENS_PER_API_BATCH:
                source_info = "Unknown source"
                if hasattr(doc, 'metadata') and isinstance(doc.metadata, dict):
                    source_info = doc.metadata.get('source', 'N/A')
                self.logger.debug(f"Warning: Document from {source_info} (index {i}) has {doc_tokens} tokens, exceeding the single batch limit of {MAX_TOKENS_PER_API_BATCH}. Skipping this document.")
                continue

            if current_batch_docs and (current_batch_tokens + doc_tokens > MAX_TOKENS_PER_API_BATCH):
                if not self.vector_db:
                    self.vector_db = Chroma.from_documents(
                        documents=current_batch_docs,
                        embedding=self.embedding_model,
                        persist_directory=self.persist_directory,
                        collection_name=self.COLLECTION_NAME
                    )
                    self.logger.debug(f"Initialized DB with first batch: {len(current_batch_docs)} docs, {current_batch_tokens} tokens.")
                else:
                    self.vector_db.add_documents(documents=current_batch_docs)
                    self.logger.debug(f"Added batch to DB: {len(current_batch_docs)} docs, {current_batch_tokens} tokens.")
                
                total_indexed_count += len(current_batch_docs)
                current_batch_docs = [doc]
                current_batch_tokens = doc_tokens
            else:
                current_batch_docs.append(doc)
                current_batch_tokens += doc_tokens
        
        if current_batch_docs:
            if not self.vector_db:
                self.vector_db = Chroma.from_documents(
                    documents=current_batch_docs,
                    embedding=self.embedding_model,
                    persist_directory=self.persist_directory,
                    collection_name=self.COLLECTION_NAME
                )
                self.logger.debug(f"Initialized DB with final/only batch: {len(current_batch_docs)} docs, {current_batch_tokens} tokens.")
            else:
                self.vector_db.add_documents(documents=current_batch_docs)
                self.logger.debug(f"Added final batch to DB: {len(current_batch_docs)} docs, {current_batch_tokens} tokens.")
            total_indexed_count += len(current_batch_docs)

        if self.vector_db and self.persist_directory:
            try:
                self.vector_db.persist()
                self.logger.debug(f"Persisted database to {self.persist_directory} with collection {self.COLLECTION_NAME}")
            except Exception as e:
                self.logger.debug(f"Error persisting database: {e}")
        
        return total_indexed_count
    
    def retrieve_relevant_code(self, query, n_results=10, filter_criteria=None):
        """Retrieve code chunks relevant to a security topic or vulnerability"""
        if not self.vector_db:
            raise ValueError("No indexed code. Call index_code_chunks first.")
            
        results = self.vector_db.similarity_search(
            query=query,
            k=n_results,
            filter=filter_criteria
        )
        
        return results
    
    def retrieve_by_file_pattern(self, query, file_pattern, n_results=10):
        """Retrieve code chunks from files matching a pattern"""
        filter_criteria = {"relative_path": {"$regex": file_pattern}}
        return self.retrieve_relevant_code(query, n_results, filter_criteria)
    
    def retrieve_by_language(self, query, language, n_results=10):
        """Retrieve code chunks from a specific programming language"""
        filter_criteria = {"language": language}
        return self.retrieve_relevant_code(query, n_results, filter_criteria)
