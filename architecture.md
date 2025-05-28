# Alder Security Scanner - Architecture Documentation

## Overview

Alder Security Scanner is an AI-powered security analysis tool that combines Large Language Model (LLM) analysis with intelligent agent-based verification to identify and validate security vulnerabilities in web application codebases. The system uses Google's Gemini AI for deep code understanding and employs a sophisticated multi-agent workflow to verify findings and reduce false positives.

## High-Level Architecture

The application follows a multi-stage pipeline architecture with clear separation of concerns:

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Repository    │───▶│  Code Processing │───▶│  Vector Database│
│   Management    │    │   & Chunking     │    │    Indexing     │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   LLM Security  │───▶│ Agent-Based     │───▶│ Report          │
│   Analysis      │    │ Verification    │    │ Generation      │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Core Components

### 1. Entry Point (`src/main.py`)

**Purpose**: Application entry point and command-line interface

**Key Responsibilities**:
- Command-line argument parsing and validation
- Environment variable loading and validation
- Token counting and cost estimation
- Orchestration initialization and execution
- GitHub integration for issue creation

**Key Features**:
- Pre-analysis token counting to prevent cost overruns
- Configurable cost limits and token limits
- Support for custom ignore directories
- Verbose logging options

### 2. Orchestrator (`src/orchestrator.py`)

**Purpose**: Central coordination of the entire analysis pipeline

**Key Responsibilities**:
- Pipeline orchestration and flow control
- Cost tracking and management
- Error handling and recovery
- Integration between all major components

**Pipeline Stages**:
1. Repository preparation and file discovery
2. Code processing and chunking
3. Vector database indexing
4. LLM-based security analysis across 10 categories
5. Agent-based verification of findings
6. Report generation and output

**Cost Management**:
- Real-time cost tracking for both embeddings and LLM calls
- Configurable cost limits with early termination
- Separate pricing tiers for different context window sizes

### 3. Repository Management (`src/repository/`)

#### `repo_manager.py`
**Purpose**: Repository access and file management

**Key Features**:
- Local repository scanning and file discovery
- Configurable ignore patterns for directories and files
- Security-conscious file access with path traversal protection
- Support for custom exclusion patterns

#### `ignore_patterns.py`
**Purpose**: Default exclusion patterns for common non-security-relevant files

**Excluded Content**:
- Build artifacts and dependencies (`node_modules`, `dist`, `build`)
- Version control and IDE files (`.git`, `.vscode`)
- Documentation and media files
- Test files and fixtures
- Configuration and environment files

### 4. Code Processing (`src/processing/`)

#### `code_processor.py`
**Purpose**: Intelligent code parsing and chunking for analysis

**Key Features**:
- **AST-Based Chunking**: Uses Tree-sitter parsers for syntax-aware code splitting
- **Language Detection**: Automatic programming language identification from file extensions
- **Intelligent Splitting**: Respects function and class boundaries when possible
- **Token Management**: Tiktoken-based token counting for cost estimation
- **Fallback Mechanisms**: Graceful degradation to character-based splitting when AST parsing fails

**Supported Languages**:
- Python, JavaScript, TypeScript, CoffeeScript
- HTML, CSS, Java, PHP, Ruby, Go
- C/C++, C#, Swift, Rust, Shell scripts
- Configuration files (JSON, YAML, XML)

#### `finding_types.py`
**Purpose**: Type definitions for security findings

**Key Types**:
- `ConsolidatedFinding`: Unified finding representation
- `SeverityLevel`: Standardized severity classifications
- Support for both SAST and LLM finding sources

#### `finding_correlator.py`
**Purpose**: Logic for correlating and deduplicating findings across different analysis methods

### 5. Vector Database (`src/database/vector_db.py`)

**Purpose**: Semantic code indexing and retrieval for contextual analysis

**Key Features**:
- **ChromaDB Integration**: Persistent vector storage with OpenAI embeddings
- **Batch Processing**: Dynamic batching based on token limits to optimize API costs
- **Semantic Search**: Code retrieval based on security-relevant queries
- **Filtering Capabilities**: Search by file patterns, programming languages, or custom criteria

**Technical Details**:
- Uses OpenAI's `text-embedding-ada-002` model
- Implements token-aware batching (250K tokens per batch)
- Persistent storage with automatic cleanup between runs

### 6. LLM Analysis (`src/analysis/` and `src/llm/`)

#### `security_analyzer.py`
**Purpose**: Core security analysis using Google Gemini

**Analysis Categories** (10 total):
1. **Authentication**: Weak credentials, session management
2. **Authorization**: Access control, privilege escalation
3. **Injection**: SQL injection, command injection, SSTI, XSS
4. **Cross-Site Scripting**: Reflected, stored, DOM-based XSS
5. **Data Protection**: Sensitive data exposure, insecure storage
6. **API Security**: Insecure API design, missing authentication
7. **Configuration**: Security misconfigurations
8. **Cryptography**: Weak algorithms, key management issues
9. **Client-Side**: JavaScript vulnerabilities, insecure storage
10. **Business Logic**: Logic flaws, race conditions, validation bypasses

**Technical Implementation**:
- Uses Gemini 2.5 Pro with function calling for structured output
- Category-specific prompts optimized for each vulnerability type
- Automatic token counting for cost tracking
- Safety settings configured to allow security-related content analysis

#### `client.py`
**Purpose**: Abstraction layer for Google Gemini API interactions

**Features**:
- Configurable model selection and parameters
- Error handling and retry logic
- Support for tools/function calling
- Comprehensive logging for debugging

### 7. Agent-Based Verification (`src/agent_workflows/finding_verifier/`)

**Purpose**: Multi-agent workflow to verify and enrich LLM findings

#### Workflow Architecture (`workflow.py`)
Uses LangGraph for orchestrating a sequential agent pipeline:

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│ Exploitability  │───▶│ Context         │───▶│ Impact          │───▶│ Synthesis       │
│ Agent           │    │ Analysis Agent  │    │ Assessment Agent│    │ Agent           │
└─────────────────┘    └─────────────────┘    └─────────────────┘    └─────────────────┘
```

#### Agent Responsibilities (`agents.py`):

1. **Exploitability Agent**:
   - Determines if vulnerabilities are actually exploitable
   - Analyzes attack vectors and prerequisites
   - Provides confidence ratings

2. **Context Analysis Agent**:
   - Examines surrounding code context
   - Identifies data sources and sinks
   - Assesses risk levels and attack scenarios

3. **Impact Assessment Agent**:
   - Evaluates business impact and consequences
   - Considers data sensitivity and system criticality
   - Provides impact severity ratings

4. **Synthesis Agent**:
   - Combines all agent analyses
   - Makes final verification decisions
   - Provides comprehensive remediation guidance
   - Assigns final priority ratings

#### State Management (`graph_state.py`)
- Maintains workflow state across agent transitions
- Preserves analysis results and intermediate findings
- Enables agent communication and data sharing

#### Tools (`tools/`)
- Code analysis utilities for agents
- Repository querying capabilities
- Vector database integration for contextual code retrieval

### 8. Report Generation (`src/reporting/report_generator.py`)

**Purpose**: Comprehensive security report creation

**Report Features**:
- **Executive Summary**: High-level findings overview with verification statistics
- **Detailed Findings**: Organized by severity with agent verification status
- **Exploitability Indicators**: Visual indicators for exploitable vs. non-exploitable findings
- **Remediation Guidance**: Specific steps for addressing each vulnerability
- **Multiple Formats**: Markdown and HTML output support

**Report Structure**:
- Severity-based organization (Critical → Informational)
- Agent verification status tracking
- Exploitability confidence ratings
- Business impact assessments
- CWE mappings where applicable

### 9. GitHub Integration (`src/github_integration.py`)

**Purpose**: Automated issue creation for CI/CD integration

**Features**:
- Automatic GitHub issue creation for verified findings
- Configurable issue templates
- Integration with GitHub Actions workflows
- Support for repository-specific configurations

## Data Flow

### 1. Repository Preparation
```
Local Repository → File Discovery → Ignore Pattern Filtering → File List
```

### 2. Code Processing
```
File List → Language Detection → AST Parsing → Code Chunking → Token Counting
```

### 3. Vector Indexing
```
Code Chunks → OpenAI Embeddings → ChromaDB Storage → Semantic Index
```

### 4. Security Analysis
```
For each of 10 categories:
  Vector Search → Relevant Code → Gemini Analysis → Raw Findings
```

### 5. Agent Verification
```
Raw Findings → Exploitability Agent → Context Agent → Impact Agent → Synthesis Agent → Verified Findings
```

### 6. Report Generation
```
Verified Findings → Severity Grouping → Report Formatting → Output Files
```

## Configuration and Deployment

### Environment Variables
- `GEMINI_API_KEY`: Google Gemini API key (required)
- `OPENAI_API_KEY`: OpenAI API key for embeddings (required)
- `GITHUB_TOKEN`: GitHub token for issue creation (optional)
- `GITHUB_REPOSITORY`: Repository slug for GitHub integration (optional)

### Deployment Options

#### Local Execution
```bash
python -m src.main --local-path /path/to/repo --output-dir ./reports
```

#### Docker Deployment
```bash
docker build -t alder-security-scanner .
docker run -v /path/to/repo:/workspace alder-security-scanner
```

#### CI/CD Integration
- GitHub Actions workflow support
- Configurable cost and token limits
- Automated issue creation
- Report artifact generation

## Cost Management

### Token Tracking
- Pre-analysis token counting prevents cost overruns
- Real-time cost tracking during analysis
- Configurable limits with early termination

### Cost Optimization
- Intelligent batching for embeddings
- AST-based chunking reduces redundant analysis
- Agent verification only on LLM findings
- Configurable analysis depth

## Security Considerations

### Input Validation
- Path traversal protection in file access
- Sanitized repository names for database paths
- Validation of API responses and tool outputs

### API Security
- Secure API key management through environment variables
- Rate limiting and error handling for external APIs
- Safety settings configured for security content analysis

### Data Privacy
- Local processing with no data retention by external services
- Temporary vector databases with automatic cleanup
- Configurable ignore patterns for sensitive files

## Extensibility

### Adding New Security Categories
1. Add category-specific prompt in `security_analyzer.py`
2. Update analysis loop in `orchestrator.py`
3. Extend report generation for new category

### Supporting New Languages
1. Add language mapping in `code_processor.py`
2. Install corresponding Tree-sitter parser
3. Update ignore patterns if needed

### Custom Agent Workflows
1. Implement new agent nodes following existing patterns
2. Update workflow graph in `workflow.py`
3. Extend state management as needed

### Alternative LLM Providers
1. Implement new client following `GeminiClient` pattern
2. Update analysis components to use new client
3. Adjust cost calculation logic

## Performance Characteristics

### Scalability
- **Small repositories** (<500K tokens): 5-10 minutes, <$1
- **Medium repositories** (~2M tokens): 10-20 minutes, $1-$4
- **Large repositories** (>5M tokens): 20+ minutes, $5+

### Bottlenecks
- LLM API calls (rate limited by provider)
- Vector embedding generation (batch optimized)
- AST parsing for very large files

### Optimization Strategies
- Parallel processing where possible
- Intelligent caching of embeddings
- Progressive analysis with early termination
- Configurable analysis depth and scope

## Error Handling and Resilience

### Graceful Degradation
- AST parsing failures fall back to character-based chunking
- Individual category failures don't stop entire analysis
- Agent verification failures preserve original findings

### Logging and Debugging
- Comprehensive logging at multiple levels
- Cost tracking and token usage reporting
- Detailed error reporting with context
- Debug mode for development and troubleshooting

### Recovery Mechanisms
- Automatic retry logic for transient API failures
- Checkpoint-based progress tracking
- Partial result preservation on early termination

## Future Enhancements

### Planned Features
- Support for additional LLM providers (Claude, GPT-4)
- Enhanced SAST tool integration
- Custom rule development framework
- Advanced attack path analysis
- Integration with security scanning platforms

### Architectural Improvements
- Microservice decomposition for better scalability
- Event-driven architecture for real-time analysis
- Plugin system for custom analyzers
- Enhanced caching and persistence layers

This architecture provides a solid foundation for security analysis while maintaining flexibility for future enhancements and integrations. 
