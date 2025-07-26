import numpy as np
from langchain_community.vectorstores import Chroma
from langchain_google_genai import GoogleGenerativeAIEmbeddings
import tiktoken
import logging
import time

class CodeVectorDatabase:
    COLLECTION_NAME = "code_documents"
    EMBEDDING_BATCH_SIZE = 20
    EMBEDDING_DELAY = 2

    def __init__(self, embedding_model=None, persist_directory="./code_db"):
        self.logger = logging.getLogger(__name__)
        self.embedding_model = embedding_model or GoogleGenerativeAIEmbeddings(model="models/text-embedding-004", task_type="RETRIEVAL_DOCUMENT")
        self.persist_directory = persist_directory
        self.vector_db = None
        try:
            self.tokenizer = tiktoken.get_encoding("cl100k_base")
        except KeyError:
            self.logger.warning("tiktoken cl100k_base encoding not found, falling back to default. Token counts for batching might be less accurate.")
            self.tokenizer = tiktoken.get_encoding("gpt2")
        
    def _get_tokens(self, text: str) -> int:
        """Helper function to count tokens in a text string."""
        return len(self.tokenizer.encode(text))

    def index_code_chunks(self, code_chunks):
        """Index code chunks for semantic search with dynamic batching based on token counts and rate limiting."""
        MAX_TOKENS_PER_CHROMA_BATCH = 250000 # Max tokens to feed into a single Chroma add/from_documents call

        if not code_chunks:
            self.logger.debug("No code chunks provided for indexing.")
            return 0

        all_docs_to_process = list(code_chunks) # Ensure it's a list for multiple iterations
        total_indexed_count = 0
        doc_cursor = 0 # Cursor to walk through all_docs_to_process

        self.logger.debug(f"Starting indexing for {len(all_docs_to_process)} total documents.")

        while doc_cursor < len(all_docs_to_process):
            # 1. Build a "Chroma batch" - a list of documents up to MAX_TOKENS_PER_CHROMA_BATCH
            current_chroma_batch_docs = []
            current_chroma_batch_tokens = 0
            start_doc_cursor_for_chroma_batch = doc_cursor

            while doc_cursor < len(all_docs_to_process):
                doc = all_docs_to_process[doc_cursor]
                doc_content = doc.page_content
                doc_tokens = 0
                try:
                    doc_tokens = self._get_tokens(doc_content)
                except Exception as e:
                    source_info = doc.metadata.get('relative_path', 'N/A') if hasattr(doc, 'metadata') and isinstance(doc.metadata, dict) else "Unknown source"
                    self.logger.warning(f"Could not tokenize document {source_info} (overall index {doc_cursor}): {e}. Skipping.")
                    doc_cursor += 1 # Move to next document
                    continue # Skip this document

                if doc_tokens > MAX_TOKENS_PER_CHROMA_BATCH:
                    source_info = doc.metadata.get('relative_path', 'N/A') if hasattr(doc, 'metadata') and isinstance(doc.metadata, dict) else "Unknown source"
                    self.logger.warning(f"Document {source_info} (overall index {doc_cursor}) has {doc_tokens} tokens, exceeding single Chroma batch limit of {MAX_TOKENS_PER_CHROMA_BATCH}. Skipping.")
                    doc_cursor += 1 # Move to next document
                    continue # Skip this large document

                if current_chroma_batch_tokens + doc_tokens > MAX_TOKENS_PER_CHROMA_BATCH and current_chroma_batch_docs:
                    break # This doc would exceed token limit for current Chroma batch, process current batch first
                
                current_chroma_batch_docs.append(doc)
                current_chroma_batch_tokens += doc_tokens
                doc_cursor += 1 # Advance cursor

            if not current_chroma_batch_docs:
                # This can happen if all remaining docs were skipped or if it's the end
                self.logger.debug("Current Chroma batch is empty. Moving on or finishing.")
                if doc_cursor >= len(all_docs_to_process):
                    break # No more documents to process at all
                else:
                    continue # Try to build next chroma batch
            
            self.logger.debug(f"Prepared Chroma batch of {len(current_chroma_batch_docs)} documents ({current_chroma_batch_tokens} tokens) from overall doc index {start_doc_cursor_for_chroma_batch} to {doc_cursor -1}.")

            # 2. Process this "Chroma batch" in smaller "Embedding sub-batches"
            for i in range(0, len(current_chroma_batch_docs), self.EMBEDDING_BATCH_SIZE):
                embedding_sub_batch = current_chroma_batch_docs[i:i + self.EMBEDDING_BATCH_SIZE]
                if not embedding_sub_batch:
                    continue

                sub_batch_doc_count = len(embedding_sub_batch)
                # sub_batch_token_count = sum(self._get_tokens(d.page_content) for d in embedding_sub_batch) # Potentially re-tokenize, or sum pre-calculated
                
                try:
                    if not self.vector_db:
                        self.logger.info(f"Initializing Chroma DB with first embedding sub-batch of {sub_batch_doc_count} documents.")
                        self.vector_db = Chroma.from_documents(
                            documents=embedding_sub_batch,
                            embedding=self.embedding_model,
                            persist_directory=self.persist_directory,
                            collection_name=self.COLLECTION_NAME
                        )
                    else:
                        self.logger.info(f"Adding embedding sub-batch of {sub_batch_doc_count} documents to Chroma DB.")
                        self.vector_db.add_documents(documents=embedding_sub_batch)
                    
                    total_indexed_count += sub_batch_doc_count
                    self.logger.debug(f"Successfully processed embedding sub-batch. Total indexed so far: {total_indexed_count}.")

                except Exception as e:
                    self.logger.error(f"Error embedding/adding sub-batch of {sub_batch_doc_count} documents to Chroma: {e}", exc_info=True)
                    # Decide how to handle error: skip batch, retry, or halt?
                    # For now, we log and continue to the next sub-batch / chroma_batch to be robust.
                    self.logger.warning("Skipping current embedding sub-batch due to error.")
                    continue # to next embedding sub-batch
                
                # Delay only if there are more embedding sub-batches to process within this Chroma batch,
                # or if there are more Chroma batches to come after this one.
                is_last_embedding_sub_batch_in_chroma_batch = (i + self.EMBEDDING_BATCH_SIZE >= len(current_chroma_batch_docs))
                is_last_chroma_batch_overall = (doc_cursor >= len(all_docs_to_process) and is_last_embedding_sub_batch_in_chroma_batch)

                if not is_last_chroma_batch_overall: # Don't sleep after the very last operation
                    self.logger.debug(f"Waiting for {self.EMBEDDING_DELAY}s after embedding sub-batch...")
                    time.sleep(self.EMBEDDING_DELAY)
            
            self.logger.debug(f"Finished processing Chroma batch. Total documents processed so far: {doc_cursor}")

        if self.vector_db and self.persist_directory:
            try:
                self.logger.info(f"Persisting database to {self.persist_directory} with collection {self.COLLECTION_NAME}. Total indexed documents: {total_indexed_count}")
                self.vector_db.persist()
            except Exception as e:
                self.logger.error(f"Error persisting database: {e}", exc_info=True)
        
        self.logger.info(f"Finished indexing. Total documents successfully indexed: {total_indexed_count} out of {len(all_docs_to_process)} considered.")
        return total_indexed_count
    
    def retrieve_relevant_code(self, query, n_results=10, filter_criteria=None):
        """Retrieve code chunks relevant to a security topic or vulnerability"""
        if not self.vector_db:
            self.logger.error("No indexed code. Call index_code_chunks first.")
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
