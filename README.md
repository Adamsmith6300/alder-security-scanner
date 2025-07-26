# Alder Security Scanner

An AI-powered security analysis tool for web applications that combines Large Language Model (LLM) analysis with intelligent agent-based verification to identify and validate security vulnerabilities in your codebase.

## 🔍 Overview

Alder Security Scanner uses Google's Gemini AI to perform comprehensive security analysis across multiple vulnerability categories, then employs a sophisticated agent workflow to verify findings and reduce false positives. The scanner provides detailed reports with exploitability assessments, business impact analysis, and actionable remediation steps.

## ✨ Key Features

- **AI-Powered Analysis**: Leverages Google Gemini 2.5 Pro for deep code understanding and vulnerability detection
- **Agent-Based Verification**: Multi-stage verification workflow that assesses exploitability, context, and impact
- **Comprehensive Coverage**: Analyzes 10 security categories including injection, XSS, authentication, authorization, and more
- **Smart Code Processing**: Uses Tree-sitter AST parsing for accurate code chunking and analysis
- **Vector Database Integration**: Efficient code retrieval using ChromaDB for contextual analysis
- **Cost Management**: Built-in cost tracking and limits to control LLM API usage
- **Multiple Deployment Options**: Run locally, in Docker, or integrate into CI/CD pipelines
- **Rich Reporting**: Generates detailed Markdown and HTML reports with severity classification

## 🛡️ Security Categories Analyzed

The scanner performs analysis across these security domains:

1. **Authentication** - Weak credentials, session management, password policies
2. **Authorization** - Access control, privilege escalation, missing checks
3. **Injection** - SQL injection, command injection, SSTI, XSS
4. **Cross-Site Scripting (XSS)** - Reflected, stored, and DOM-based XSS
5. **Data Protection** - Sensitive data exposure, insecure storage/transmission
6. **API Security** - Insecure API design, missing authentication/authorization
7. **Configuration** - Security misconfigurations in frameworks and servers
8. **Cryptography** - Weak algorithms, improper key management, insecure RNG
9. **Client-Side** - JavaScript vulnerabilities, insecure data storage
10. **Business Logic** - Logic flaws, race conditions, validation bypasses

## 🚀 Quick Start

### Prerequisites

- Docker
- Google Gemini API key
- OpenAI API key (for embeddings)

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/adamsmith6300/alder-security-scanner.git
   cd alder-security-scanner
   ```

2. **Set up environment variables:**
   ```bash
   cp .env.example .env
   # Edit .env and add your API keys:
   # GOOGLE_API_KEY=your_google_api_key
   # OPENAI_API_KEY=your_openai_api_key
   ```

3. **Build the Docker image:**
   ```bash
   docker build -t alder-security-scanner .
   ```

## 📖 Usage

### Docker Execution

```bash
# Scan a repository using Docker
./local.sh /path/to/your/repository
```

### Docker Script Options

The `local.sh` script builds and runs the scanner in a Docker container with the following features:

- **Automatic Docker image building**: The script builds the image locally on each run
- **Environment variable injection**: Your API keys from `.env` are passed to the container
- **Volume mounting**: The target repository and reports directory are mounted for analysis
- **Report generation**: Security reports are saved to `./security-reports/` directory

### Configuration

You can customize the analysis by modifying the Docker script or the scanner's built-in defaults:

- **Maximum tokens**: 5,000,000 tokens per scan (configurable)
- **Maximum cost**: $5.00 USD per scan (configurable)
- **Ignore patterns**: Common directories like `node_modules`, `dist`, `build` are automatically ignored

## 📊 Example Usage Scenarios

### 1. Quick Security Assessment

```bash
# Fast scan of a small project
./local.sh ./my-web-app
```

### 2. Comprehensive Enterprise Scan

```bash
# Full scan of a large codebase
./local.sh ./enterprise-app
```

### 3. Scanning Remote Repositories

```bash
# Clone and scan a repository
git clone https://github.com/user/repo.git
./local.sh ./repo
```

## ⏱️ Performance & Cost

- **Analysis Time**: Scans typically take 5-10 minutes for medium-sized codebases, with larger repositories potentially taking longer
- **Cost Estimates**:
  - Small repositories (<500K tokens): Usually under $1
  - Medium repositories (~2M tokens): $1-$4
  - Large repositories (>5M tokens): $5+ (costs are automatically limited to $5.00 by default)
- **Token Limits**: Default maximum of 5M tokens per scan with automatic cost management

## 🏗️ Architecture

The scanner follows a multi-stage analysis pipeline:

1. **Repository Preparation**: Scans and filters files based on ignore patterns
2. **Code Processing**: Uses Tree-sitter for AST-based code chunking
3. **Vector Indexing**: Creates embeddings for efficient code retrieval
4. **LLM Analysis**: Gemini analyzes code chunks for each security category
5. **Agent Verification**: Multi-agent workflow verifies findings:
   - **Exploitability Agent**: Assesses if vulnerabilities are exploitable
   - **Context Agent**: Analyzes attack scenarios and risk levels
   - **Impact Agent**: Evaluates business impact and consequences
   - **Synthesis Agent**: Combines analyses and provides final recommendations
6. **Report Generation**: Creates comprehensive reports with verified findings

📖 **For detailed architecture documentation, see [Architecture.md](architecture.md)** - This comprehensive guide explains the system design, component interactions, data flow, and extensibility patterns.

## 📋 Supported File Types

The scanner analyzes these programming languages and file types:

- **Python** (.py)
- **JavaScript** (.js, .jsx)
- **TypeScript** (.ts, .tsx)
- **CoffeeScript** (.coffee)
- **HTML** (.html)
- **CSS** (.css)
- **Java** (.java)
- **PHP** (.php)
- **Ruby** (.rb)
- **Go** (.go)
- **C/C++** (.c, .cpp, .h)
- **C#** (.cs)
- **Swift** (.swift)
- **Rust** (.rs)
- **Shell Scripts** (.sh)
- **Configuration Files** (.json, .yaml, .yml, .xml)
- **SQL** (.sql)
- **GraphQL** (.graphql)

## 🚫 Limitations

- **Language Support**: Best results with Python, JavaScript, and TypeScript; other languages have basic support
- **Context Window**: Limited by LLM context windows; very large files may be truncated
- **API Dependencies**: Requires internet connection and valid API keys for Gemini and OpenAI
- **Cost Considerations**: Analysis costs scale with codebase size and complexity
- **False Positives**: While agent verification reduces false positives, manual review is still recommended
- **Static Analysis Only**: Does not perform dynamic analysis or runtime testing

## 📊 Report Format

The scanner generates detailed reports including:

- **Executive Summary**: Overview of findings and verification status
- **Severity Classification**: Critical, High, Medium, Low, Informational
- **Exploitability Assessment**: Exploitable, Not Exploitable, Uncertain
- **Detailed Findings**: Each finding includes:
  - File location and line numbers
  - Code snippets
  - Exploitability analysis with confidence scores
  - Risk and impact assessment
  - Attack scenarios
  - Remediation steps
  - CWE mappings where applicable

### Example Report Output

Here's a sample of what the generated security report looks like:

```markdown
# Security Analysis Report: MyApp
*Generated: 2025-05-27 20:27:09 UTC*

## Executive Summary

This report summarizes potential security findings identified through Large Language Model (LLM) analysis and verified through an AI agent workflow.

### Verification Summary

- **Total Findings**: 33
- **Agent Verified**: 33
- **Exploitable**: 25
- **Not Exploitable**: 3
- **Uncertain**: 5

### Findings Summary

| Severity      | Code Findings | Exploitable | Not Exploitable | Uncertain |
|---------------|---------------|-------------|-----------------|-----------|
| Critical      | 18            | 18          | 0               | 0         |
| High          | 11            | 7           | 1               | 3         |
| Medium        | 3             | 0           | 1               | 2         |
| Low           | 1             | 0           | 1               | 0         |

## Detailed Findings

### Critical Findings

#### 1. SQL injection vulnerability in the `/items/product/:id` endpoint [P0-Critical] 🔴 Exploitable
**Source:** Category: injection
**File:** `app.js:18`
**CWE:** CWE-89
**Verification Status:** Verified By Agent Workflow

**Description:**
SQL injection vulnerability allows attackers to execute arbitrary SQL commands due to unsanitized user input in the 'id' parameter.

**🔍 Exploitability Analysis:**
- **Status:** Exploitable
- **Confidence:** 90%
- **Reasoning:** The `id` parameter is directly concatenated into the SQL query without sanitization, allowing arbitrary SQL injection.
- **Data Source Analysis:** User-controlled input from URL path parameter.

**📊 Risk & Impact Analysis:**
- **Risk Level:** High
- **Business Impact:** Critical
- **Attack Scenario:** Attacker can send crafted requests to execute arbitrary SQL commands
- **Potential Consequences:**
  - Complete database compromise
  - Unauthorized data access and modification
  - Service disruption

**Code Snippet:**
```javascript
app.get('/items/product/:id', (req, res) => {
  const id = req.params.id;
  const sql = `SELECT * FROM items WHERE id = ${id}`;
  // Vulnerable: direct concatenation
```

**🔧 Remediation Steps:**
1. Use parameterized queries or prepared statements
2. Implement input validation for the 'id' parameter
3. Apply principle of least privilege to database connections

**🤖 AI Analysis Summary:**
High-confidence exploitable vulnerability with critical business impact. Immediate remediation required.

---
```

## 🔧 Configuration

### Environment Variables

```bash
# Required
GOOGLE_API_KEY=your_google_api_key
OPENAI_API_KEY=your_openai_api_key

# Optional (for GitHub integration)
GITHUB_TOKEN=your_github_token
GITHUB_REPOSITORY=owner/repo-name
INPUT_CREATE_ISSUES=true
```

### Ignore Patterns

The scanner automatically ignores common directories and files. You can customize this by:

1. Using `--extra-ignore-dirs` for additional directories
2. Modifying `src/repository/ignore_patterns.py` for permanent changes

Default ignored directories include:
- Version control: `.git`, `.svn`
- Dependencies: `node_modules`, `vendor`, `venv`
- Build artifacts: `dist`, `build`, `target`
- IDE files: `.vscode`, `.idea`
- And many more...

## 🔗 GitHub Action Integration

While this repository doesn't include a pre-built GitHub Action, you can easily integrate the scanner into your CI/CD pipeline by:

1. Publishing the Docker image to a container registry
2. Creating a custom GitHub Action that uses the published image
3. Using the provided Docker configuration as a starting point

The scanner includes GitHub integration features for creating issues from findings when appropriate environment variables are set.

## 🤝 Contributing

We welcome contributions! To get started:

1. **Understand the Architecture**: Read the [Architecture.md](architecture.md) documentation to understand the system design, component structure, and data flow. This is essential for making meaningful contributions.

2. **Review the Codebase**: The architecture documentation provides a roadmap to navigate the codebase effectively.

3. **Make a pull request!**

### Key Areas for Contribution

- **New Security Categories**: Add additional vulnerability detection categories
- **Language Support**: Extend support for additional programming languages
- **Agent Workflows**: Enhance or create new verification agent workflows
- **LLM Providers**: Add support for additional LLM providers (Claude, GPT-4, etc.)
- **Report Formats**: Create new report output formats
- **Performance Optimizations**: Improve analysis speed and cost efficiency


## 📄 License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- **Issues**: Report bugs and request features via [GitHub Issues](https://github.com/adamsmith6300/alder-security-scanner/issues)

---

**⚠️ Disclaimer**: This tool is designed to assist in security analysis but should not be the only security measure. Always perform manual security reviews and testing in addition to automated scanning. 
