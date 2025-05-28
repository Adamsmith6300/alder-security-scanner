from typing import Optional, List, Dict, Any
import logging

from tree_sitter import Language, Parser, Tree, Node
# Explicitly import the language bindings
import tree_sitter_python as tspython
import tree_sitter_javascript as tsjs
# import tree_sitter_typescript as tsts # For both typescript and tsx

logger = logging.getLogger(__name__)

class TreeSitterParser:
    _parsers: Dict[str, Parser] = {}
    _languages: Dict[str, Language] = {}

    # Maps common language names/extensions to a direct language function from imported modules
    # The value should be the result of calling .language() on the imported module, wrapped in Language()
    LANGUAGE_PROVIDERS = {
        "python": lambda: Language(tspython.language()),
        "javascript": lambda: Language(tsjs.language()),
        # "typescript": lambda: Language(tsts.language()), # ts and tsx covered by tree_sitter_typescript
        # "tsx": lambda: Language(tsts.language()),
    }
    # Map for resolving various user inputs to the keys in LANGUAGE_PROVIDERS
    LANGUAGE_NAME_MAP = {
        "python": "python",
        "py": "python",
        "javascript": "javascript",
        "js": "javascript",
        # "typescript": "typescript",
        # "ts": "typescript",
        # "tsx": "tsx", 
    }

    def __init__(self):
        logger.debug(f"TreeSitterParser initializing...")
        # Pre-load languages to populate caches and catch errors early
        for lang_map_key in self.LANGUAGE_NAME_MAP.keys():
            logger.debug(f"Pre-loading language mapped by key: '{lang_map_key}'")
            self._get_language(lang_map_key)
        logger.debug(f"TreeSitterParser initialized. Cached languages: {list(self._languages.keys())}, Parsers: {list(self._parsers.keys())}")

    def _get_language(self, language_name: str) -> Optional[Language]:
        logger.debug(f"Requesting tree-sitter Language object for: '{language_name}'")
        # First, resolve the input language_name (e.g., "py") to our canonical key (e.g., "python")
        canonical_name = self.LANGUAGE_NAME_MAP.get(language_name.lower())
        if not canonical_name:
            logger.warning(f"Unsupported or unknown input language name for TreeSitterParser: '{language_name}'")
            return None
        logger.debug(f"Resolved language name: '{canonical_name}' for input '{language_name}'")

        if canonical_name not in self._languages:
            logger.debug(f"Language '{canonical_name}' not in cache. Attempting to load directly.")
            try:
                provider = self.LANGUAGE_PROVIDERS.get(canonical_name)
                if not provider:
                    logger.error(f"No language provider defined for canonical name: '{canonical_name}'")
                    return None
                
                lang_obj = provider() # Call the lambda to get Language(module.language())
                
                if not isinstance(lang_obj, Language):
                    # This check should ideally not fail if Language(module.language()) works
                    logger.error(f"CRITICAL: Language object for '{canonical_name}' is NOT a tree_sitter.Language instance after direct creation. Type: {type(lang_obj)}")
                    return None

                self._languages[canonical_name] = lang_obj
                logger.info(f"Successfully created and cached tree-sitter Language for '{canonical_name}'.")
            except Exception as e:
                logger.error(f"Error creating tree-sitter Language for '{canonical_name}': {e}", exc_info=True)
                return None
        else:
            logger.debug(f"Language '{canonical_name}' found in cache.")
        return self._languages.get(canonical_name)

    def _get_parser(self, language_name: str) -> Optional[Parser]:
        logger.debug(f"Requesting tree-sitter Parser for: '{language_name}'")
        # Use the canonical name for cache lookups and operations
        canonical_name = self.LANGUAGE_NAME_MAP.get(language_name.lower())
        if not canonical_name:
            logger.warning(f"Cannot get parser for '{language_name}', unknown input language name.")
            return None

        lang_obj = self._get_language(language_name) # _get_language now uses canonical_name for its internal logic and caching
        if not lang_obj:
            logger.warning(f"Cannot get parser for '{language_name}' (canonical: '{canonical_name}'), language object is None.")
            return None

        if canonical_name not in self._parsers:
            logger.debug(f"Parser for '{canonical_name}' not in cache. Creating and caching new parser.")
            parser = Parser(lang_obj) 
            self._parsers[canonical_name] = parser
        else:
            logger.debug(f"Parser for '{canonical_name}' found in cache.")
        return self._parsers.get(canonical_name)

    def parse(self, code_bytes: bytes, language_name: str) -> Optional[Tree]:
        logger.debug(f"Attempting to parse code. Language: '{language_name}', Code length: {len(code_bytes)} bytes.")
        parser = self._get_parser(language_name) # _get_parser handles canonical name resolution
        if not parser:
            logger.error(f"Could not get parser for language: '{language_name}'. Parsing aborted.")
            return None
        try:
            tree = parser.parse(code_bytes)
            logger.debug(f"Code parsed successfully for language '{language_name}'. Root node: {tree.root_node.type if tree and tree.root_node else 'None'}")
            return tree
        except Exception as e:
            logger.error(f"Error during tree-sitter parsing for {language_name}: {e}", exc_info=True)
            return None

    def get_node_at_position(self, tree: Tree, line: int, column: int) -> Optional[Node]:
        logger.debug(f"Getting node at position: Line {line}, Column {column}")
        if not tree or tree.root_node is None:
            logger.warning("Cannot get node at position: Tree or root node is None.")
            return None
        int_line = int(line)
        int_column = int(column)
        node = tree.root_node.descendant_for_point_range((int_line, int_column), (int_line, int_column))
        logger.debug(f"Node found at position ({int_line},{int_column}): Type='{node.type if node else 'None'}'")
        return node
        
    def get_enclosing_function_node(self, start_node: Node, language_name: str) -> Optional[Node]:
        logger.debug(f"Getting enclosing function/block for node type '{start_node.type if start_node else 'None'}', lang: '{language_name}'")

        func_node_types_map = {
            "python": ["function_definition", "class_definition"], 
            "javascript": ["function_declaration", "function_expression", "arrow_function", "method_definition", "class_declaration"],
            "typescript": ["function_declaration", "function_expression", "arrow_function", "method_definition", "class_declaration", "interface_declaration"],
            "tsx": ["function_declaration", "function_expression", "arrow_function", "method_definition", "class_declaration", "interface_declaration"],
        }
        
        # Use canonical name for looking up func_node_types
        canonical_lang_name = self.LANGUAGE_NAME_MAP.get(language_name.lower())
        if not canonical_lang_name:
            logger.warning(f"Cannot get enclosing function: language '{language_name}' not mapped to a canonical name.")
            return None
            
        func_node_types = func_node_types_map.get(canonical_lang_name, [])
        if not func_node_types:
            logger.warning(f"No function node types defined for canonical language: '{canonical_lang_name}' in get_enclosing_function_node.")
            return None
        logger.debug(f"Target enclosing node types for '{canonical_lang_name}': {func_node_types}")

        current_node = start_node
        path_traced = []
        while current_node:
            path_traced.append(current_node.type)
            if current_node.type in func_node_types:
                logger.debug(f"Found enclosing node: Type='{current_node.type}'. Path traced up: {path_traced}")
                return current_node
            current_node = current_node.parent
        logger.debug(f"No enclosing function/block node found. Path traced up: {path_traced}")
        return None

    def get_node_text(self, node: Node, code_bytes: bytes) -> str:
        if not node:
            logger.debug("get_node_text called with None node.")
            return ""
        text = code_bytes[node.start_byte:node.end_byte].decode('utf-8', errors='replace')
        return text

    def run_query(self, tree: Tree, query_string: str, language_name: str) -> List[Dict[str, Any]]:
        logger.debug(f"Running tree-sitter query for language '{language_name}'. Query (first 50 chars): '{query_string[:50]}...'")
        # _get_language (called by _get_parser if not cached, or here directly) will use canonical name logic
        lang_obj = self._get_language(language_name) 
        if not lang_obj or not tree or not tree.root_node:
            logger.warning("Cannot run query: Language object, tree, or root node is None.")
            return []

        try:
            query = lang_obj.query(query_string)
            logger.debug(f"Tree-sitter query object created successfully.")
            
            processed_matches = []
            match_count = 0
            for match in query.matches(tree.root_node):
                match_count += 1
                current_match_details = {}
                
                # Handle the actual API format: match is a tuple (pattern_index, captures_dict)
                if isinstance(match, tuple) and len(match) > 1:
                    captures_dict = match[1]
                    if isinstance(captures_dict, dict):
                        # captures_dict maps capture_name -> [list of nodes]
                        for capture_name, node_list in captures_dict.items():
                            if node_list and len(node_list) > 0:
                                # Take the first node if multiple nodes are captured
                                current_match_details[capture_name] = node_list[0]
                    else:
                        logger.warning(f"Unexpected captures format: {type(captures_dict)}")
                else:
                    logger.warning(f"Unexpected match format: {type(match)}")
                
                if current_match_details:
                    processed_matches.append(current_match_details)
            
            logger.debug(f"Query executed. Found {match_count} raw matches, yielding {len(processed_matches)} processed matches.")
            return processed_matches
        except Exception as e:
            logger.error(f"Error running tree-sitter query for {language_name}: '{query_string}'. Error: {e}", exc_info=True)
            return []
