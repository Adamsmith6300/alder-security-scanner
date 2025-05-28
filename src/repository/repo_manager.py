import os
from pathlib import Path
import logging
import fnmatch
from typing import Optional

# Import default ignore patterns
from .ignore_patterns import DEFAULT_IGNORE_DIRS, DEFAULT_IGNORE_FILE_PATTERNS

# Get a logger instance for this module
logger = logging.getLogger(__name__)

class RepositoryManager:
    def __init__(self, local_path, temp_dir="./temp_repos", extra_ignore_dirs=None):
        self.local_path = local_path
        self.temp_dir = Path(temp_dir)
        self.repo_dir = None
        
        # Initialize instance ignore lists by copying the defaults
        self.ignoreDirs = DEFAULT_IGNORE_DIRS.copy()
        if extra_ignore_dirs:
            if isinstance(extra_ignore_dirs, list):
                self.ignoreDirs.update(extra_ignore_dirs)
                logger.debug(f"Added {len(extra_ignore_dirs)} extra directories to ignore list.")
            else:
                logger.warning("extra_ignore_dirs provided but not a list. Ignoring.")

        # Correct variable name to match import
        self.ignoreFilePatterns = DEFAULT_IGNORE_FILE_PATTERNS.copy()
        
    def prepare_repository(self):
        """Set up repository for analysis from local path"""
        logger.debug("Preparing repository...")
        
        logger.debug(f"Using local repository path: {self.local_path}")
        # Use existing local repository
        self.repo_dir = Path(self.local_path)
        
        if not self.repo_dir.exists():
            logger.debug(f"Local repository path does not exist: {self.local_path}")
            raise ValueError(f"Local path does not exist: {self.local_path}")
            
        return self.repo_dir
    
    def get_file_paths(self):
        """Get all relevant files for analysis, respecting instance ignore lists."""
        if not self.repo_dir:
            logger.debug("Attempted to get file paths before repository was prepared.")
            raise ValueError("Repository not prepared. Call prepare_repository first.")

        logger.debug("Scanning repository for files...")
        
        current_exclude_dirs = self.ignoreDirs
        # Use instance ignoreFilePatterns
        current_ignore_patterns = self.ignoreFilePatterns
        logger.debug(f"Current ignore patterns: {current_ignore_patterns}")
        file_paths = []
        # Use os.fspath() for compatibility with Path objects
        repo_root_str = os.fspath(self.repo_dir)
        
        for root, dirs, files in os.walk(repo_root_str, topdown=True):
            # Modify dirs in place to prevent walking into excluded directories
            # Compare just the dir name, not the full path yet
            dirs[:] = [d for d in dirs if d not in current_exclude_dirs]

            for file in files:
                # Check if the file matches any of the ignore patterns
                skip_file = False
                logger.debug(f"Checking file {file} against ignore patterns:")
                for pattern in current_ignore_patterns:
                    if fnmatch.fnmatch(file, pattern):
                        logger.debug(f"    Skipping file {file}: Matches pattern '{pattern}'")
                        skip_file = True
                        break  # No need to check other patterns
                
                if skip_file:
                    continue
                    
                # Construct full path
                file_path = os.path.join(root, file)
                
                # Double-check absolute path against ignored dirs (more robust)
                # This requires constructing potential ignored paths - might be simpler to rely on dirs[:] exclusion
                # Example check (potentially complex):
                # relative_root = os.path.relpath(root, repo_root_str)
                # if any(part in current_exclude_dirs for part in Path(relative_root).parts):
                #      continue # Already excluded by dirs[:] modification
                
                file_paths.append(file_path)
        logger.debug(f"File paths: {file_paths}")
        logger.debug(f"Found {len(file_paths)} files matching criteria after exclusions.")
        return file_paths

    def get_file_content(self, relative_file_path: str) -> Optional[str]:
        """Reads and returns the content of a file given its relative path from the repo root."""
        if not self.repo_dir:
            logger.error("get_file_content: Repository not prepared. Call prepare_repository first.")
            # Or raise ValueError("Repository not prepared. Call prepare_repository first.")
            return None

        logger.debug(f"Attempting to read content of file: {relative_file_path}")

        try:
            # Ensure the relative_file_path is truly relative and does not try to escape
            # os.path.abspath will resolve based on CWD if path is absolute, so we want to join from repo_dir
            # Path.resolve() will make it absolute and canonical, which is good.
            # Path.is_relative_to() (Python 3.9+) would be ideal here.
            
            # Construct the full, absolute path
            full_file_path = (self.repo_dir / relative_file_path).resolve()

            # Security check: Ensure the resolved path is still within the self.repo_dir
            # This prevents directory traversal if relative_file_path is something like "../../../../../etc/passwd"
            if self.repo_dir.resolve() not in full_file_path.parents and full_file_path != self.repo_dir.resolve():
                 # A more robust check for Python < 3.9:
                 # common_prefix = os.path.commonpath([str(self.repo_dir.resolve()), str(full_file_path)])
                 # if common_prefix != str(self.repo_dir.resolve()):
                if not str(full_file_path).startswith(str(self.repo_dir.resolve()) + os.sep):
                    logger.error(
                        f"get_file_content: Potential directory traversal attempt. Path '{relative_file_path}' resolves outside repository root '{self.repo_dir}'. Resolved path: {full_file_path}"
                    )
                    return None

            if not full_file_path.is_file():
                logger.warning(f"get_file_content: File does not exist or is not a file: {full_file_path} (from relative: {relative_file_path})")
                return None

            with open(full_file_path, 'r', encoding='utf-8', errors='replace') as f:
                content = f.read()
            logger.debug(f"Successfully read content of {full_file_path} (length: {len(content)} chars).")
            return content
        except Exception as e:
            logger.error(f"get_file_content: Error reading file '{relative_file_path}' (resolved: {full_file_path if 'full_file_path' in locals() else relative_file_path}): {e}", exc_info=True)
            return None
