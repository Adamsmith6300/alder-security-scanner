import os
import tiktoken
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain.docstore.document import Document
import magic
import logging
from tree_sitter import Parser, Language
from tree_sitter_languages import get_language, get_parser

logger = logging.getLogger(__name__)

# Define node types that represent potential chunk boundaries
# These might need refinement based on desired granularity
AST_SPLIT_NODES = {
    'python': ['function_definition', 'class_definition'],
    'javascript': ['function_declaration', 'class_declaration', 'lexical_declaration', 'expression_statement'],
    'typescript': ['function_declaration', 'class_declaration', 'lexical_declaration', 'expression_statement', 'interface_declaration', 'type_alias_declaration'],
    'tsx': ['function_declaration', 'class_declaration', 'lexical_declaration', 'expression_statement', 'interface_declaration', 'type_alias_declaration'],
    'coffeescript': ['function_definition', 'class_definition', 'method_definition', 'expression_statement'],
    'java': ['method_declaration', 'class_declaration', 'interface_declaration', 'enum_declaration', 'constructor_declaration'],
}

# Define a maximum chunk limit per file
MAX_CHUNKS_PER_FILE = 20

class CodeProcessor:
    def __init__(self, repo_manager, chunk_size=1000, chunk_overlap=500):
        self.repo_manager = repo_manager
        self.chunk_size = chunk_size
        self.chunk_overlap = chunk_overlap
        self.encoder = tiktoken.get_encoding("cl100k_base")
        self.parser = Parser()
        self.tree_sitter_languages = {}
        self._setup_tree_sitter()
        logger.debug(f"CodeProcessor initialized with tree-sitter languages: {list(self.tree_sitter_languages.keys())}")

    def _setup_tree_sitter(self):
        """Load tree-sitter languages"""
        languages_to_load = {
            'python': 'python',
            'javascript': 'javascript',
            'typescript': 'typescript',
            'tsx': 'tsx',
            'coffeescript': 'coffeescript',
            'java': 'java'
        }
        for lang_name, ts_lang_name in languages_to_load.items():
            try:
                language = get_language(ts_lang_name)
                self.tree_sitter_languages[lang_name] = language
                logger.debug(f"Successfully loaded tree-sitter language: {lang_name}")
            except Exception as e:
                logger.debug(f"Could not load tree-sitter language '{ts_lang_name}': {e}. AST splitting will not be available for .{lang_name} files.")

    def is_text_file(self, file_path):
        """Check if file is a text file that can be processed"""
        try:
            mime = magic.Magic(mime=True)
            file_type = mime.from_file(file_path)
            is_text = file_type.startswith('text/') or 'script' in file_type
            logger.debug(f"File type check for {file_path}: mime={file_type}, is_text={is_text}")
            return is_text
        except magic.MagicException as e:
            logger.debug(f"Could not determine file type for {file_path} using libmagic: {e}")
            # Fallback: Check if extension suggests it might be text-based
            common_text_exts = ['.py', '.js', '.ts', '.java', '.c', '.cpp', '.h', '.html', '.css', '.json', '.yaml', '.yml', '.md', '.txt', '.coffee']
            ext = os.path.splitext(file_path)[1].lower()
            is_common_text = ext in common_text_exts
            logger.debug(f"Fallback file type check for {file_path}: extension={ext}, is_common_text={is_common_text}")
            return is_common_text
        except Exception as e:
            logger.debug(f"Unexpected error during file type check for {file_path}: {e}")
            return False

    def get_language_from_extension(self, file_path):
        """Determine programming language from file extension"""
        extension_mapping = {
            '.py': 'python',
            '.js': 'javascript',
            '.ts': 'typescript',
            '.jsx': 'javascript',
            '.tsx': 'tsx',
            '.html': 'html',
            '.css': 'css',
            '.java': 'java',
            '.php': 'php',
            '.rb': 'ruby',
            '.go': 'go',
            '.c': 'c',
            '.cpp': 'cpp',
            '.cs': 'csharp',
            '.swift': 'swift',
            '.rs': 'rust',
            '.sh': 'bash',
            '.json': 'json',
            '.xml': 'xml',
            '.yaml': 'yaml',
            '.yml': 'yaml',
            '.md': 'markdown',
            '.sql': 'sql',
            '.graphql': 'graphql',
            '.kt': 'kotlin',
            '.dart': 'dart',
            '.r': 'r',
            '.scala': 'scala',
            '.coffee': 'coffeescript',
        }
        ext = os.path.splitext(file_path)[1].lower()
        lang = extension_mapping.get(ext, 'plaintext')
        if lang == 'typescript' and ext == '.tsx':
            return 'tsx'
        if lang == 'javascript' and ext == '.jsx':
            return 'jsx'
        return lang

    def _chunk_code_with_ast(self, content, language, file_path, relative_path):
        """Chunks code using tree-sitter AST nodes."""
        ts_language = self.tree_sitter_languages.get(language)
        if not ts_language:
            return None

        self.parser.set_language(ts_language)
        try:
            tree = self.parser.parse(bytes(content, "utf8"))
            root_node = tree.root_node
        except Exception as e:
            logger.debug(f"Tree-sitter failed to parse {relative_path} ({language}): {e}. Falling back to default splitter.")
            return None

        chunks = []
        nodes_to_split = AST_SPLIT_NODES.get(language, [])
        if not nodes_to_split:
             logger.debug(f"No AST split nodes defined for {language}. Falling back to default splitter.")
             return None

        start_byte = 0
        current_chunk_nodes = []

        # Helper to finalize a chunk
        def finalize_chunk(nodes, end_byte):
            if not nodes:
                return
            chunk_start_byte = nodes[0].start_byte
            chunk_end_byte = end_byte
            chunk_content = content[chunk_start_byte:chunk_end_byte].strip()

            if not chunk_content:
                return

            # Use RecursiveCharacterTextSplitter for chunks potentially larger than chunk_size
            # or as a simple way to handle overlap initially.
            # A more sophisticated approach could manage overlap based on AST nodes.
            splitter = RecursiveCharacterTextSplitter(
                chunk_size=self.chunk_size,
                chunk_overlap=self.chunk_overlap,
                length_function=len
            )
            sub_chunks = splitter.split_text(chunk_content)

            for sub_chunk_content in sub_chunks:
                 metadata = {
                    'file_path': str(file_path),
                    'relative_path': relative_path,
                    'language': language,
                    'token_count': len(self.encoder.encode(sub_chunk_content)),
                    'source': 'ast'
                }
                 chunks.append(Document(page_content=sub_chunk_content, metadata=metadata))

        # Iterate through top-level nodes
        for node in root_node.children:
            is_split_node = node.type in nodes_to_split
            # If it's a significant node type OR if adding it exceeds chunk size (heuristic)
            # For simplicity, we are splitting primarily by node type defined in AST_SPLIT_NODES
            if is_split_node and current_chunk_nodes:
                 finalize_chunk(current_chunk_nodes, node.start_byte)
                 current_chunk_nodes = [node]
            else:
                current_chunk_nodes.append(node)

        finalize_chunk(current_chunk_nodes, root_node.end_byte)

        if chunks:
             logger.debug(f"AST splitting created {len(chunks)} chunks for {relative_path}")
             return chunks
        else:
             logger.debug(f"AST splitting resulted in 0 chunks for {relative_path}. Falling back.")
             return None


    def chunk_code_file(self, file_path, relative_path):
        """Process a single code file into chunks with metadata"""
        logger.debug(f"Processing file: {relative_path}")
        file_size = 0
        try:
            file_size = os.path.getsize(file_path)
            if not self.is_text_file(file_path):
                logger.debug(f"Skipping non-text file: {relative_path} (Size: {file_size} bytes)")
                return []
        except OSError as e:
             logger.debug(f"Could not get size or check type for {relative_path}: {e}")
             return [] # Skip if we can't access file info

        logger.debug(f"Reading file: {relative_path} (Size: {file_size} bytes)")

        try:
            with open(file_path, 'rb') as f:
                 content_bytes = f.read()
            content = content_bytes.decode('utf-8', errors='replace')
        except Exception as e:
            logger.debug(f"Error reading {relative_path}: {e}")
            return []

        if not content.strip():
            logger.debug(f"Skipping empty file: {relative_path}")
            return []

        language = self.get_language_from_extension(file_path)
        logger.debug(f"Detected language '{language}' for file: {relative_path}")

        chunks = None
        source_method = "unknown"
        # Attempt AST-based splitting first
        if language in self.tree_sitter_languages:
            try:
                 chunks = self._chunk_code_with_ast(content, language, file_path, relative_path)
                 if chunks is not None:
                     source_method = "ast"
            except Exception as e:
                 logger.debug(f"Unexpected error during AST chunking for {relative_path}: {e}", exc_info=True)
                 chunks = None

        # Fallback to RecursiveCharacterTextSplitter
        if chunks is None:
            source_method = "recursive"
            logger.debug(f"Using fallback RecursiveCharacterTextSplitter for {relative_path} (language: {language})" )
            try:
                # Use LangChain's language mapping if available
                try:
                    splitter = RecursiveCharacterTextSplitter.from_language(
                        language=language,
                        chunk_size=self.chunk_size,
                        chunk_overlap=self.chunk_overlap,
                        length_function=len # Ensure consistent length function if needed
                    )
                    logger.debug(f"Using LangChain language-specific splitter ({language}) for {relative_path}")
                except ValueError:
                    logger.debug(f"Language '{language}' not supported by LangChain splitter, using default RecursiveCharacterTextSplitter for {relative_path}")
                    splitter = RecursiveCharacterTextSplitter(
                        chunk_size=self.chunk_size,
                        chunk_overlap=self.chunk_overlap,
                        length_function=len
                    )

                # Use create_documents which handles metadata correctly
                langchain_docs = splitter.create_documents(
                    texts=[content],
                    metadatas=[{ # Pass metadata for the whole document
                        'file_path': str(file_path),
                        'relative_path': relative_path,
                        'language': language,
                        'token_count': len(self.encoder.encode(content)),
                        'source': source_method # Use variable for source method
                    }]
                )
                chunks = langchain_docs
                logger.debug(f"Fallback splitter created {len(chunks)} chunks for {relative_path}")

            except Exception as e:
                 logger.debug(f"Error creating chunks using fallback splitter for file {relative_path}: {e}", exc_info=True)
                 return []
        
        # Log final chunk count for the file
        final_chunk_count = len(chunks) if chunks is not None else 0
        if final_chunk_count > MAX_CHUNKS_PER_FILE:
             logger.debug(f"Skipping file {relative_path} (Size: {file_size} bytes): Generated {final_chunk_count} chunks, exceeding the limit of {MAX_CHUNKS_PER_FILE}.")
             return [] # Return empty list to skip this file

        logger.debug(f"Generated {final_chunk_count} chunks for {relative_path} (Size: {file_size} bytes, Method: {source_method})")
        return chunks if chunks is not None else []


    def process_codebase(self):
        """Process the entire codebase into chunks"""
        logger.debug("Starting codebase processing...")
        
        repo_dir = self.repo_manager.repo_dir
        file_paths = self.repo_manager.get_file_paths()
        num_files = len(file_paths)
        logger.debug(f"Processing {num_files} files found by RepositoryManager.")

        all_chunks = []
        file_chunk_counts = {} # Dictionary to store chunk counts per file
        processed_files = 0
        skipped_files = 0
        skipped_due_to_chunks = 0 # New counter for chunk limit skips

        for file_path in file_paths:
            relative_path = os.path.relpath(file_path, repo_dir)
            file_chunks = self.chunk_code_file(file_path, relative_path)
            if file_chunks:
                 chunk_count = len(file_chunks)
                 all_chunks.extend(file_chunks)
                 file_chunk_counts[relative_path] = chunk_count # Store count
                 processed_files += 1
            else:
                 # Need to differentiate why it was skipped - this is tricky without modifying return signature
                 # For now, assume if chunk_code_file returned empty, it was skipped for *some* reason (non-text, empty, or chunk limit)
                 skipped_files += 1
                 # We logged the specific reason within chunk_code_file
            
            # Show progress every 10%
            progress_increment = max(1, num_files // 10)
            if (processed_files + skipped_files) % progress_increment == 0:
                logger.debug(f"Processed {processed_files + skipped_files}/{num_files} files...")

        logger.debug(f"Finished codebase processing. Processed: {processed_files}, Skipped: {skipped_files}. Total chunks created: {len(all_chunks)}.")

        # Debug information about files with most chunks - implementation detail
        if all_chunks:
            file_chunk_counts = {}
            for chunk in all_chunks:
                file = chunk.metadata.get('relative_path', 'unknown')
                file_chunk_counts[file] = file_chunk_counts.get(file, 0) + 1
                
            # Show top 5 files by chunk count
            logger.debug("Top 5 files by generated chunk count:")
            for i, (file, count) in enumerate(sorted(file_chunk_counts.items(), key=lambda x: x[1], reverse=True)[:5]):
                logger.debug(f"  {i+1}. {file}: {count} chunks")

        return all_chunks

# Ensure the logger is configured if running this script directly or if not configured by the main app
if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
