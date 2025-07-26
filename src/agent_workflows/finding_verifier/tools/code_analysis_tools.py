import logging
from typing import Dict, Any, List, Tuple
import os # For path.splitext

# Corrected import paths assuming this file is in src/agent_workflows/finding_verifier/tools/
from ....repository.repo_manager import RepositoryManager
from ....database.vector_db import CodeVectorDatabase
from .tree_sitter_parser import TreeSitterParser

logger = logging.getLogger(__name__)

# Define protection check patterns (can be expanded and moved to a config)
PROTECTION_CHECKS_CONFIG = [
    {
        "name": "Python: Unsafe SQL Execution (f-string)",
        "language": "python",
        "query": """
        (call
          function: (attribute object: (_) attribute: (identifier) @method_name)
          arguments: (argument_list 
            (string 
              (interpolation) @interpolation
            ) @f_string_arg
          )
          (#match? @method_name "execute")
        )
        """,
        "description": "Identified a potential unsafe SQL execution using an f-string directly in a database execute call. This is a high risk for SQL injection if the f-string contains user-controlled data.",
        "type": "lack_of_protection"
    },
    {
        "name": "Python: Unsafe SQL Execution (string concatenation)",
        "language": "python",
        "query": """
        (call
            function: (attribute object: (_) attribute: (identifier) @method_name)
            arguments: (argument_list (binary_operator operator: "+") @concat_arg)
            (#match? @method_name "execute")
        )
        """,
        "description": "Identified a potential unsafe SQL execution using string concatenation directly in a database execute call. This is a high risk for SQL injection if concatenated strings include user-controlled data.",
        "type": "lack_of_protection"
    },
    {
        "name": "Python: Unsafe SQL Execution (.format)",
        "language": "python",
        "query": """
        (call
            function: (attribute object: (_) attribute: (identifier) @method_name)
            arguments: (argument_list 
                (call
                    function: (attribute object: (string) @str_format_target attribute: (identifier) @format_call)
                )
            )
            (#match? @method_name "execute")
            (#match? @format_call "format")
        )
        """,
        "description": "Identified a potential unsafe SQL execution using .format() on a string directly in a database execute call. This can be a risk for SQL injection if format arguments are user-controlled.",
        "type": "lack_of_protection"
    },
    {
        "name": "Python: HTML Escaping (html.escape)",
        "language": "python",
        "query": """
        (call
            function: (attribute object: (identifier) @module_name attribute: (identifier) @func_name)
            (#match? @module_name "html")
            (#match? @func_name "escape")
        ) @html_escape_call
        """,
        "description": "Identified usage of html.escape(), which is a good practice for preventing XSS by sanitizing HTML content.",
        "type": "protection_present"
    },
    {
        "name": "Python: HTML Escaping (markupsafe.escape)",
        "language": "python",
        "query": """
        (call
            function: (attribute object: (identifier) @module_name attribute: (identifier) @func_name)
            (#match? @module_name "markupsafe")
            (#match? @func_name "escape")
        ) @markupsafe_escape_call
        """,
        "description": "Identified usage of markupsafe.escape(), which is a good practice for preventing XSS by sanitizing HTML content (common in Flask/Jinja2 environments).",
        "type": "protection_present"
    }
    # Add more checks for other languages (JS, TS) or other Python patterns
]

# Data source classification patterns for identifying where data originates
DATA_SOURCE_PATTERNS = {
    "user_controlled": [
        "request.form", "request.json", "request.args", "request.files", "request.data",
        "request.POST", "request.GET", "request.FILES", "request.body",
        "input(", "sys.argv", "os.environ.get", "getenv(",
        "flask.request", "django.request", "fastapi.Request",
        "params", "query_params", "path_params", "form_data",
        "cookies", "headers", "session"
    ],
    "internal_generation": [
        "uuid.uuid4()", "uuid4()", "datetime.now()", "time.time()",
        "random.", "secrets.", "hashlib.", "base64.",
        "os.path.join", "pathlib.Path", "Path(",
        "str(uuid", "generate_", "create_", "make_"
    ],
    "trusted_source": [
        ".query(", ".get(", ".filter(", ".find(", ".select(",
        "config.", "settings.", "env.get(", "getenv(",
        "database.", "db.", "model.", "orm.",
        "cache.", "redis.", "memcache."
    ],
    "file_operations": [
        "open(", "file(", "read(", "write(", "load(",
        "json.load", "yaml.load", "pickle.load",
        "os.listdir", "glob.glob", "pathlib"
    ]
}

# Tree-sitter queries for finding variable assignments and function calls
VARIABLE_ASSIGNMENT_QUERIES = {
    "python": {
        "assignment": """
        (assignment
          left: (identifier) @var_name
          right: (_) @assignment_value
        )
        """,
        "function_call_assignment": """
        (assignment
          left: (identifier) @var_name
          right: (call
            function: (_) @function_name
            arguments: (_) @arguments
          ) @call_expression
        )
        """,
        "attribute_assignment": """
        (assignment
          left: (identifier) @var_name
          right: (attribute
            object: (_) @object
            attribute: (_) @attribute
          ) @attribute_expression
        )
        """,
        "function_parameter": """
        (function_definition
          name: (_) @func_name
          parameters: (parameters
            (identifier) @param_name
          )
        )
        """
    }
}

class CodeAnalysisTools:
    def __init__(self, repo_manager: RepositoryManager, vector_db: CodeVectorDatabase):
        self.repo_manager = repo_manager
        self.vector_db = vector_db
        self.ts_parser = TreeSitterParser()
        logger.debug(f"CodeAnalysisTools initialized with RepoManager: {type(repo_manager).__name__}, VectorDB: {type(vector_db).__name__}, TreeSitterParser: {type(self.ts_parser).__name__}")

    def _get_language_from_file_path(self, file_path: str) -> str:
        logger.debug(f"Attempting to determine language from file path: {file_path}")
        _, ext = os.path.splitext(file_path)
        ext = ext.lower().lstrip('.')
        lang = "python" # Default
        if ext in ["py"]:
            lang = "python"
        elif ext in ["js"]:
            lang = "javascript"
        elif ext in ["ts", "tsx"]:
            lang = "typescript"
        elif ext in ["java"]:
            lang = "java"
        else:
            logger.warning(f"Could not determine specific language from file extension: '{ext}' for file {file_path}. Defaulting to 'python'.")
        logger.debug(f"Determined language: '{lang}' for file path: {file_path}")
        return lang

    def trace_execution_path(self, finding: Dict[str, Any]) -> str:
        """
        Identifies the structural context (enclosing function/class) of a vulnerability using tree-sitter.
        """
        description = finding.get("description", "N/A")
        file_path = finding.get("affected_files", [None])[0]
        line_number_1_indexed = finding.get("line_number")
        logger.debug(f"trace_execution_path called for finding: '{description[:50]}...' in {file_path}:{line_number_1_indexed}")

        if not file_path:
            logger.warning("trace_execution_path: Affected file path not available.")
            return "Execution Path Trace Skipped: Affected file path not available."
        if line_number_1_indexed is None:
            logger.warning(f"trace_execution_path: Line number not available for {file_path}.")
            return f"Execution Path Trace Skipped: Line number not available for {file_path}."

        language = self._get_language_from_file_path(file_path)
        ts_line_number_0_indexed = line_number_1_indexed - 1
        logger.debug(f"Language for AST: {language}, 0-indexed line: {ts_line_number_0_indexed}")

        try:
            content_str = self.repo_manager.get_file_content(file_path)
            if not content_str:
                logger.warning(f"trace_execution_path: Could not retrieve content for {file_path}.")
                return f"Execution Path Trace Failed: Could not retrieve content for {file_path}."
            logger.debug(f"Retrieved content for {file_path} (length: {len(content_str)})")
            
            content_bytes = content_str.encode('utf-8')
            tree = self.ts_parser.parse(code_bytes=content_bytes, language_name=language)

            if not tree or not tree.root_node:
                logger.warning(f"trace_execution_path: Could not parse {file_path} with tree-sitter for language {language}.")
                return f"Execution Path Trace Failed: Could not parse {file_path} with tree-sitter for language {language}."
            logger.debug(f"Successfully parsed {file_path} with tree-sitter.")

            node_at_vuln_line = self.ts_parser.get_node_at_position(tree, ts_line_number_0_indexed, 0)
            logger.debug(f"Node at vuln line ({ts_line_number_0_indexed}, 0): {node_at_vuln_line.type if node_at_vuln_line else 'None'}")
            
            if not node_at_vuln_line:
                return (f"Execution Path Trace Info: Could not identify a specific AST node at line {line_number_1_indexed} "
                        f"in {file_path}. The vulnerability context is the line itself within the file.")

            enclosing_structural_node = self.ts_parser.get_enclosing_function_node(node_at_vuln_line, language)
            logger.debug(f"Enclosing structural node: {enclosing_structural_node.type if enclosing_structural_node else 'None'}")
            
            if enclosing_structural_node:
                node_type = enclosing_structural_node.type
                node_text = self.ts_parser.get_node_text(enclosing_structural_node, content_bytes)
                
                # Try to get a name for the function/class if possible (language-dependent)
                node_name = "N/A"
                if language == "python":
                    name_child = enclosing_structural_node.child_by_field_name("name")
                    if name_child:
                        node_name = self.ts_parser.get_node_text(name_child, content_bytes)
                elif language in ["javascript", "typescript"]: # JS/TS might have 'name' or be anonymous
                    # For JS/TS, 'identifier' child of certain nodes or via properties for classes
                    # This is a simplified heuristic for common function/class declarations
                    if node_type in ["function_declaration", "method_definition", "class_declaration"]:
                         name_node = enclosing_structural_node.child_by_field_name('name') # Common field
                         if not name_node and node_type == "method_definition": # class methods often have direct identifier child
                             name_node = enclosing_structural_node.child(0) if enclosing_structural_node.child_count > 0 and enclosing_structural_node.child(0).type == 'property_identifier' else None
                         if name_node:
                            node_name = self.ts_parser.get_node_text(name_node, content_bytes)
                
                result_str = (
                    f"Execution Path Trace (AST based):\n"
                    f"Vulnerability (Description: '{description}') is in file '{file_path}' at line {line_number_1_indexed}.\n"
                    f"It appears within the '{node_type}' (name: '{node_name}' if available).\n"
                    f"Full text of this structural element:\n---\n{node_text}\n---"
                )
                node_text_summary = node_text[:100] + "..."
                logger.debug(f"Found enclosing block: type='{node_type}', text_summary='{node_text_summary}'")
                return result_str
            else:
                logger.debug("No specific enclosing structural block (function/class) found.")
                return (
                    f"Execution Path Trace (AST based):\n"
                    f"Vulnerability (Description: '{description}') is in file '{file_path}' at line {line_number_1_indexed}.\n"
                    f"It does not appear to be within a deeper recognized structural block (like a function or class). "
                    f"Review the surrounding code in the file for broader context."
                )

        except Exception as e:
            logger.error(f"Error during AST-based execution path tracing for {file_path}: {e}", exc_info=True)
            return (f"Error during AST-based execution path tracing for '{description}' in '{file_path}': {e}. "
                    f"The vulnerability context is line {line_number_1_indexed} in the file.")

    def get_code_context_around_line(self, file_path: str, line_number: int, finding: Dict[str, Any], window_size: int = 10) -> str:
        """
        Retrieves a semantic code context (e.g., enclosing function/block) around a specific line.
        Falls back to a window of lines if semantic context retrieval fails.
        line_number is assumed to be 1-indexed from the finding, converted to 0-indexed for tree-sitter.
        """
        ts_line_number = line_number - 1 # Convert to 0-indexed for tree-sitter
        language = self._get_language_from_file_path(file_path)
        logger.debug(f"get_code_context_around_line called for {file_path}:{line_number} (0-indexed: {ts_line_number}), lang: {language}")

        try:
            content_str = self.repo_manager.get_file_content(file_path)
            if not content_str:
                logger.warning(f"get_code_context_around_line: Could not retrieve content for {file_path}.")
                return f"Error: Could not retrieve content for {file_path}."
            logger.debug(f"Retrieved content for {file_path} (length: {len(content_str)}) for context retrieval.")
            
            content_bytes = content_str.encode('utf-8')
            tree = self.ts_parser.parse(code_bytes=content_bytes, language_name=language)

            if tree and tree.root_node:
                logger.debug(f"Successfully parsed {file_path} for semantic context.")
                node_at_line = self.ts_parser.get_node_at_position(tree, ts_line_number, 0)
                logger.debug(f"Node at line ({ts_line_number},0) for context: {node_at_line.type if node_at_line else 'None'}")
                if node_at_line:
                    enclosing_block = self.ts_parser.get_enclosing_function_node(node_at_line, language)
                    logger.debug(f"Enclosing block for context: {enclosing_block.type if enclosing_block else 'None'}")
                    if enclosing_block:
                        block_text = self.ts_parser.get_node_text(enclosing_block, content_bytes)
                        context_type = enclosing_block.type
                        logger.debug(f"Returning semantic context (type: {context_type}), length: {len(block_text)} chars.")
                        return f"Semantic Context (type: {context_type}):\n---\n{block_text}\n---"
                    else:
                        logger.debug(f"Tree-sitter: Could not find enclosing function/block for {file_path}:{line_number}. Falling back to line window.")
                else:
                    logger.debug(f"Tree-sitter: Could not find node at {file_path}:{line_number}. Falling back to line window.")
            else:
                logger.debug(f"Tree-sitter: Failed to parse {file_path}. Falling back to line window.")

            logger.debug("Falling back to line window context.")
            lines = content_str.splitlines()
            start_idx = int(max(0, ts_line_number - window_size))
            end_idx = int(min(len(lines), ts_line_number + window_size + 1))
            context_lines = lines[start_idx:end_idx]
            joined_lines = '\n'.join(context_lines)
            result_str = f"Line Window Context (lines {start_idx+1}-{end_idx}):\n---\n{joined_lines}\n---"
            logger.debug(f"Returning line window context, {len(context_lines)} lines.")
            return result_str
        except Exception as e:
            logger.error(f"Error getting code context for {file_path}:{line_number} (tree-sitter or fallback): {e}", exc_info=True)
            # Fallback logic as before
            content_str_fallback = self.repo_manager.get_file_content(file_path)
            if content_str_fallback:
                 lines = content_str_fallback.splitlines()
                 start_idx = int(max(0, ts_line_number - window_size))
                 end_idx = int(min(len(lines), ts_line_number + window_size + 1))
                 context_lines = lines[start_idx:end_idx]
                 logger.debug("Returning line window context due to error in context retrieval.")
                 joined_lines = "\n".join(context_lines)
                 result_str = f"Line Window Context (due to error, lines {start_idx+1}-{end_idx}):\n---\n{joined_lines}\n---"
                 logger.debug(f"Returning line window context due to error in context retrieval.")
                 return result_str
            return f"Error: Could not retrieve code context for {file_path}:{line_number}. Details: {e}"

    def check_for_protections(self, finding: Dict[str, Any]) -> str:
        """
        Checks for predefined security protection patterns (or lack thereof) in the file related to the finding.
        Uses tree-sitter queries for identified patterns.
        """
        file_path = finding.get("affected_files", [None])[0]
        logger.debug(f"check_for_protections called for file: {file_path}")
        if not file_path:
            logger.warning("check_for_protections: Affected file path not available.")
            return "Protection Check Skipped: Affected file path not available in the finding."

        language = self._get_language_from_file_path(file_path)
        logger.debug(f"Language for protection checks: {language}")

        try:
            content_str = self.repo_manager.get_file_content(file_path)
            if not content_str:
                logger.warning(f"check_for_protections: Could not retrieve content for {file_path}.")
                return f"Protection Check Skipped: Could not retrieve content for {file_path}."
            logger.debug(f"Retrieved content for {file_path} (length: {len(content_str)}) for protection checks.")
            
            content_bytes = content_str.encode('utf-8')
            tree = self.ts_parser.parse(code_bytes=content_bytes, language_name=language)

            if not tree or not tree.root_node:
                logger.warning(f"check_for_protections: Failed to parse {file_path} with tree-sitter for language {language}.")
                return f"Protection Check Skipped: Failed to parse {file_path} with tree-sitter for language {language}."
            logger.debug(f"Successfully parsed {file_path} for protection checks.")

            detected_patterns = []
            applicable_checks = [chk for chk in PROTECTION_CHECKS_CONFIG if chk["language"] == language]
            logger.debug(f"Found {len(applicable_checks)} applicable protection checks for language '{language}'.")

            if not applicable_checks:
                return f"Protection Check Info: No specific protection checks configured for language '{language}'."

            for check_config in applicable_checks:
                logger.debug(f"Running protection check: '{check_config['name']}'")
                matches = self.ts_parser.run_query(tree, check_config["query"], language)
                logger.debug(f"Check '{check_config['name']}' found {len(matches)} matches.")
                if matches:
                    for i, match_data in enumerate(matches):
                        first_node_in_match = next(iter(match_data.values()), None) if match_data else None
                        line_num_of_match = "N/A"
                        text_of_match = "N/A"
                        if first_node_in_match:
                            line_num_of_match = first_node_in_match.start_point[0] + 1
                            text_of_match = self.ts_parser.get_node_text(first_node_in_match, content_bytes)
                            text_of_match = text_of_match[:100] + "..." if len(text_of_match) > 100 else text_of_match
                        
                        pattern_info = (
                            f"- Pattern: {check_config['name']}\n"
                            f"  Description: {check_config['description']}\n"
                            f"  Type: {check_config['type']}\n"
                            f"  Location: Approx. line {line_num_of_match} (Snippet: '{text_of_match}')"
                        )
                        detected_patterns.append(pattern_info)
                        logger.debug(f"  Detected pattern instance {i+1} for '{check_config['name']}': Line {line_num_of_match}, Snippet: '{text_of_match}'")
            
            if not detected_patterns:
                logger.debug("No specific pre-defined protection/anti-protection patterns were detected.")
                return "Protection Check Result: No specific pre-defined protection/anti-protection patterns were detected in the file."
            
            result_summary = "Protection Check Results:\n" + "\n".join(detected_patterns)
            logger.debug(f"Protection check finished. Summary (first 200 chars): {result_summary[:200]}...")
            return result_summary
        except Exception as e:
            logger.error(f"Error during protection check for {file_path}: {e}", exc_info=True)
            return f"Error during protection check for {file_path}. Details: {e}"

    def search_related_code_snippets(self, query: str, n_results: int = 3) -> List[Dict[str, Any]]:
        """
        Searches for code snippets semantically related to the query using the vector database.
        """
        logger.debug(f"search_related_code_snippets called with query: '{query[:100]}...', n_results: {n_results}")
        try:
            results = self.vector_db.retrieve_relevant_code(query=query, n_results=n_results)
            logger.debug(f"Vector DB retrieve_relevant_code returned {len(results)} raw documents.")
            
            formatted_results = []
            for i, doc in enumerate(results):
                content = "Content not available"
                metadata = {"file_path": "Unknown", "error": "Initial error state"}
                if hasattr(doc, 'page_content') and hasattr(doc, 'metadata'):
                    content = doc.page_content
                    metadata = doc.metadata 
                    logger.debug(f"  Processing doc {i+1} (LangChain-like): metadata={metadata}, content snippet (first 50): {content[:50]}...")
                elif isinstance(doc, dict) and "page_content" in doc and "metadata" in doc:
                    content = doc["page_content"]
                    metadata = doc["metadata"]
                    logger.debug(f"  Processing doc {i+1} (dict-like): metadata={metadata}, content snippet (first 50): {content[:50]}...")
                else:
                    content = str(doc)
                    metadata={"file_path": "Unknown", "error": "Unexpected document structure"}
                    logger.warning(f"  Processing doc {i+1}: Unexpected structure. Converted to string. Snippet (first 50): {content[:50]}...")
                
                formatted_results.append({
                    "content": content,
                    "metadata": metadata 
                })
            logger.debug(f"Formatted {len(formatted_results)} documents for search_related_code_snippets.")
            return formatted_results
        except Exception as e:
            logger.error(f"Error in search_related_code_snippets: {e}", exc_info=True)
            return [{"content": f"Error searching related code: {e}", "metadata": {"file_path": "Error"}}] 

    def trace_data_flow_backward(self, finding: Dict[str, Any], max_depth: int = 5) -> str:
        """
        Traces backward from the vulnerable variable to find its data sources.
        Identifies if data comes from user input, internal generation, or trusted sources.
        """
        file_path = finding.get("affected_files", [None])[0]
        line_number_1_indexed = finding.get("line_number")
        description = finding.get("description", "N/A")
        
        logger.debug(f"trace_data_flow_backward called for finding: '{description[:50]}...' in {file_path}:{line_number_1_indexed}")
        
        if not file_path:
            logger.warning("trace_data_flow_backward: Affected file path not available.")
            return "Data Flow Trace Skipped: Affected file path not available."
        if line_number_1_indexed is None:
            logger.warning(f"trace_data_flow_backward: Line number not available for {file_path}.")
            return f"Data Flow Trace Skipped: Line number not available for {file_path}."

        # Ensure line_number is properly converted to integer
        try:
            line_number_1_indexed = int(line_number_1_indexed)
        except (ValueError, TypeError):
            logger.warning(f"trace_data_flow_backward: Invalid line number '{line_number_1_indexed}' for {file_path}.")
            return f"Data Flow Trace Skipped: Invalid line number '{line_number_1_indexed}' for {file_path}."

        language = self._get_language_from_file_path(file_path)
        ts_line_number_0_indexed = line_number_1_indexed - 1
        
        try:
            content_str = self.repo_manager.get_file_content(file_path)
            if not content_str:
                logger.warning(f"trace_data_flow_backward: Could not retrieve content for {file_path}.")
                return f"Data Flow Trace Failed: Could not retrieve content for {file_path}."
            
            content_bytes = content_str.encode('utf-8')
            tree = self.ts_parser.parse(code_bytes=content_bytes, language_name=language)
            
            if not tree or not tree.root_node:
                logger.warning(f"trace_data_flow_backward: Could not parse {file_path} with tree-sitter for language {language}.")
                return f"Data Flow Trace Failed: Could not parse {file_path} with tree-sitter for language {language}."
            
            # Step 1: Find the vulnerable variable at the specified line
            vulnerable_variable = self._extract_vulnerable_variable(tree, content_bytes, ts_line_number_0_indexed, language)
            if not vulnerable_variable:
                return f"Data Flow Trace: Could not identify vulnerable variable at line {line_number_1_indexed} in {file_path}."
            
            logger.debug(f"Identified vulnerable variable: '{vulnerable_variable}'")
            
            # Step 2: Trace the variable's data sources
            data_sources = self._trace_variable_sources(tree, content_bytes, vulnerable_variable, language, max_depth)
            
            # Step 3: Classify the data sources
            classification = self._classify_data_sources(data_sources)
            
            # Step 4: Search for related assignments across the codebase
            cross_file_sources = self._search_cross_file_assignments(vulnerable_variable)
            
            # Step 5: Generate comprehensive report
            return self._generate_data_flow_report(vulnerable_variable, data_sources, classification, cross_file_sources, file_path, line_number_1_indexed)
            
        except Exception as e:
            logger.error(f"Error during data flow tracing for {file_path}: {e}", exc_info=True)
            return f"Error during data flow tracing for '{description}' in '{file_path}': {e}"

    def _extract_vulnerable_variable(self, tree, content_bytes: bytes, line_number: int, language: str) -> str:
        """Extract the variable name that's being used vulnerably at the specified line."""
        node_at_line = self.ts_parser.get_node_at_position(tree, line_number, 0)
        if not node_at_line:
            return None
        
        def find_identifiers(node):
            identifiers = []
            if node.type == "identifier":
                identifiers.append(self.ts_parser.get_node_text(node, content_bytes))
            for child in node.children:
                identifiers.extend(find_identifiers(child))
            return identifiers
        
        # Get the line content to help identify the main variable
        lines = content_bytes.decode('utf-8').splitlines()
        # Ensure line_number is an integer for list indexing
        line_idx = int(line_number)
        if line_idx < len(lines):
            line_content = lines[line_idx]
            logger.debug(f"Vulnerable line content: {line_content}")
            
            # Find identifiers in the vulnerable line
            identifiers = find_identifiers(node_at_line)
            if identifiers:
                # Return the first identifier that's likely a variable (not a function name)
                for identifier in identifiers:
                    if not any(keyword in line_content for keyword in ["def ", "class ", "import ", "from "]):
                        return identifier
                return identifiers[0]  # Fallback to first identifier
        
        return None

    def _trace_variable_sources(self, tree, content_bytes: bytes, variable_name: str, language: str, max_depth: int) -> List[Dict[str, Any]]:
        """Trace where a variable gets its values from within the current file."""
        sources = []
        
        if language not in VARIABLE_ASSIGNMENT_QUERIES:
            logger.warning(f"No variable assignment queries defined for language: {language}")
            return sources
        
        queries = VARIABLE_ASSIGNMENT_QUERIES[language]
        
        # Find all assignments to this variable
        for query_name, query_string in queries.items():
            try:
                matches = self.ts_parser.run_query(tree, query_string, language)
                for match in matches:
                    var_name_node = match.get("var_name") or match.get("param_name")
                    if var_name_node:
                        var_name = self.ts_parser.get_node_text(var_name_node, content_bytes)
                        if var_name == variable_name:
                            source_info = self._extract_assignment_info(match, content_bytes, query_name)
                            if source_info:
                                sources.append(source_info)
            except Exception as e:
                logger.debug(f"Error running query {query_name}: {e}")
        
        return sources

    def _extract_assignment_info(self, match: Dict[str, Any], content_bytes: bytes, query_type: str) -> Dict[str, Any]:
        """Extract detailed information about a variable assignment."""
        info = {
            "query_type": query_type,
            "line_number": None,
            "assignment_text": "",
            "source_type": "unknown",
            "details": {}
        }
        
        # Get line number from any node in the match
        first_node = next(iter(match.values()), None)
        if first_node:
            # Ensure line number is properly converted to integer
            info["line_number"] = int(first_node.start_point[0]) + 1
        
        # Extract assignment details based on query type
        if query_type == "assignment":
            assignment_value = match.get("assignment_value")
            if assignment_value:
                info["assignment_text"] = self.ts_parser.get_node_text(assignment_value, content_bytes)
                info["source_type"] = self._determine_source_type(info["assignment_text"])
        
        elif query_type == "function_call_assignment":
            function_name = match.get("function_name")
            arguments = match.get("arguments")
            if function_name:
                func_text = self.ts_parser.get_node_text(function_name, content_bytes)
                args_text = self.ts_parser.get_node_text(arguments, content_bytes) if arguments else ""
                info["assignment_text"] = f"{func_text}({args_text})"
                info["source_type"] = self._determine_source_type(info["assignment_text"])
                info["details"]["function_name"] = func_text
                info["details"]["arguments"] = args_text
        
        elif query_type == "attribute_assignment":
            attribute_expr = match.get("attribute_expression")
            if attribute_expr:
                info["assignment_text"] = self.ts_parser.get_node_text(attribute_expr, content_bytes)
                info["source_type"] = self._determine_source_type(info["assignment_text"])
        
        elif query_type == "function_parameter":
            func_name = match.get("func_name")
            if func_name:
                info["assignment_text"] = f"function parameter in {self.ts_parser.get_node_text(func_name, content_bytes)}"
                info["source_type"] = "function_parameter"
                info["details"]["function_name"] = self.ts_parser.get_node_text(func_name, content_bytes)
        
        return info

    def _determine_source_type(self, assignment_text: str) -> str:
        """Determine the type of data source based on assignment text."""
        assignment_lower = assignment_text.lower()
        
        # Check each category of data sources
        for source_type, patterns in DATA_SOURCE_PATTERNS.items():
            for pattern in patterns:
                if pattern.lower() in assignment_lower:
                    return source_type
        
        # Additional heuristics
        if any(keyword in assignment_lower for keyword in ["request", "input", "param", "arg"]):
            return "user_controlled"
        elif any(keyword in assignment_lower for keyword in ["config", "setting", "env", "database", "db"]):
            return "trusted_source"
        elif any(keyword in assignment_lower for keyword in ["uuid", "random", "time", "generate"]):
            return "internal_generation"
        
        return "unknown"

    def _classify_data_sources(self, data_sources: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Classify and summarize the data sources found."""
        classification = {
            "user_controlled": [],
            "internal_generation": [],
            "trusted_source": [],
            "file_operations": [],
            "function_parameter": [],
            "unknown": [],
            "overall_risk": "unknown"
        }
        
        for source in data_sources:
            source_type = source.get("source_type", "unknown")
            classification[source_type].append(source)
        
        # Determine overall risk level
        if classification["user_controlled"]:
            classification["overall_risk"] = "high"
        elif classification["function_parameter"]:
            classification["overall_risk"] = "medium"  # Depends on how function is called
        elif classification["internal_generation"]:
            classification["overall_risk"] = "low"
        elif classification["trusted_source"]:
            classification["overall_risk"] = "low"
        else:
            classification["overall_risk"] = "unknown"
        
        return classification

    def _search_cross_file_assignments(self, variable_name: str) -> List[Dict[str, Any]]:
        """Search for assignments to this variable across the codebase using vector search."""
        try:
            # Search for patterns where this variable might be assigned
            search_queries = [
                f"{variable_name} =",
                f"{variable_name} = request",
                f"{variable_name} = generate",
                f"def create_{variable_name}",
                f"def set_{variable_name}"
            ]
            
            cross_file_results = []
            for query in search_queries:
                try:
                    results = self.vector_db.retrieve_relevant_code(query=query, n_results=2)
                    for result in results:
                        if hasattr(result, 'page_content') and hasattr(result, 'metadata'):
                            content = result.page_content
                            metadata = result.metadata
                        elif isinstance(result, dict):
                            content = result.get("page_content", str(result))
                            metadata = result.get("metadata", {})
                        else:
                            continue
                        
                        # Only include if it actually contains the variable name
                        if variable_name in content:
                            cross_file_results.append({
                                "query": query,
                                "content": content[:200] + "..." if len(content) > 200 else content,
                                "file_path": metadata.get("file_path", "Unknown"),
                                "source_type": self._determine_source_type(content)
                            })
                except Exception as e:
                    logger.debug(f"Error in cross-file search for query '{query}': {e}")
            
            return cross_file_results
        except Exception as e:
            logger.debug(f"Error in cross-file assignment search: {e}")
            return []

    def _generate_data_flow_report(self, variable_name: str, data_sources: List[Dict[str, Any]], 
                                 classification: Dict[str, Any], cross_file_sources: List[Dict[str, Any]], 
                                 file_path: str, line_number: int) -> str:
        """Generate a comprehensive data flow analysis report."""
        report_lines = [
            f"Data Flow Analysis for variable '{variable_name}' at {file_path}:{line_number}",
            "=" * 80,
            ""
        ]
        
        # Overall risk assessment
        overall_risk = classification.get("overall_risk", "unknown")
        report_lines.extend([
            f"OVERALL RISK LEVEL: {overall_risk.upper()}",
            ""
        ])
        
        # Summary of sources found
        total_sources = len(data_sources)
        if total_sources == 0:
            report_lines.extend([
                "No direct assignments to this variable found in the current file.",
                "This could indicate:",
                "- Variable is a function parameter (check function calls)",
                "- Variable is assigned in a different file",
                "- Variable is a global or class attribute",
                ""
            ])
        else:
            report_lines.extend([
                f"Found {total_sources} assignment(s) to '{variable_name}' in current file:",
                ""
            ])
        
        # Detailed source analysis
        for category, sources in classification.items():
            if category == "overall_risk" or not sources:
                continue
            
            report_lines.extend([
                f"{category.upper().replace('_', ' ')} SOURCES ({len(sources)}):",
                "-" * 40
            ])
            
            for source in sources:
                line_num = source.get("line_number", "Unknown")
                assignment_text = source.get("assignment_text", "")
                query_type = source.get("query_type", "")
                
                report_lines.extend([
                    f"  Line {line_num}: {assignment_text}",
                    f"  Type: {query_type}",
                    ""
                ])
        
        # Cross-file analysis
        if cross_file_sources:
            report_lines.extend([
                "CROSS-FILE ANALYSIS:",
                "-" * 40
            ])
            
            for source in cross_file_sources[:5]:  # Limit to top 5 results
                file_path_result = source.get("file_path", "Unknown")
                content = source.get("content", "")
                source_type = source.get("source_type", "unknown")
                
                report_lines.extend([
                    f"  File: {file_path_result}",
                    f"  Source Type: {source_type}",
                    f"  Content: {content}",
                    ""
                ])
        
        # Risk interpretation
        report_lines.extend([
            "RISK INTERPRETATION:",
            "-" * 40
        ])
        
        if classification["user_controlled"]:
            report_lines.append("⚠️  HIGH RISK: Variable receives data from user-controlled sources")
        elif classification["function_parameter"]:
            report_lines.append("⚠️  MEDIUM RISK: Variable is a function parameter - check how function is called")
        elif classification["internal_generation"]:
            report_lines.append("✅ LOW RISK: Variable contains internally generated data")
        elif classification["trusted_source"]:
            report_lines.append("✅ LOW RISK: Variable contains data from trusted sources (config, database)")
        else:
            report_lines.append("❓ UNKNOWN RISK: Could not determine data source - manual review needed")
        
        return "\n".join(report_lines) 
