# AST-Grep Rules Interactive Database

A SQL-queryable database system for ast-grep security rules that allows you to explore and query the rule collection like a database.

## Features

- **SQL Queries**: Execute arbitrary SQL queries against the rules database
- **Full-text Search**: Search across rule messages and notes using FTS5
- **Statistics**: Get insights about rule distribution by language, severity, CWE references
- **Multiple Output Formats**: Results in table, JSON, or CSV format
- **Interactive CLI**: Easy-to-use command-line interface

## Installation

```bash
# Install dependencies
pip install click PyYAML

# Make the script executable
chmod +x rule_db.py
```

## Quick Start

```bash
# Initialize the database with all rules
python3 rule_db.py init

# Show database statistics
python3 rule_db.py stats

# List available languages
python3 rule_db.py languages

# Show rules for a specific language
python3 rule_db.py lang python
```

## Usage Examples

### SQL Queries

```bash
# Find all warning-level rules for Python
python3 rule_db.py query "SELECT id, message FROM rules WHERE language = 'python' AND severity = 'warning'"

# Count rules by language
python3 rule_db.py query "SELECT language, COUNT(*) as count FROM rules GROUP BY language ORDER BY count DESC"

# Find rules related to JWT
python3 rule_db.py query "SELECT * FROM rules WHERE message LIKE '%JWT%' OR note LIKE '%JWT%'"

# Get rules with specific CWE references
python3 rule_db.py query "SELECT id, language, message FROM rules WHERE cwe_references LIKE '%798%'"

# Export results as JSON
python3 rule_db.py query "SELECT * FROM rules WHERE language = 'go'" --format json

# Export as CSV
python3 rule_db.py query "SELECT id, language, severity FROM rules" --format csv
```

### Full-text Search

```bash
# Search for hardcoded secrets
python3 rule_db.py search "hardcoded secret"

# Search for JWT-related rules
python3 rule_db.py search "JWT token"

# Search for SQL injection patterns
python3 rule_db.py search "SQL injection"
```

### Language-specific Queries

```bash
# Show all Python rules
python3 rule_db.py lang python

# Show all TypeScript rules
python3 rule_db.py lang typescript
```

## Database Schema

The database contains a `rules` table with the following columns:

- `id`: Unique rule identifier
- `language`: Programming language (python, java, javascript, etc.)
- `severity`: Rule severity (warning, error, info)
- `message`: Short rule description
- `note`: Detailed explanation with references
- `category`: Rule category (extracted from file path)
- `file_path`: Path to the original YAML file
- `cwe_references`: Comma-separated CWE numbers
- `ast_grep_pattern`: JSON-serialized ast-grep rule pattern
- `utils_patterns`: JSON-serialized utility patterns
- `created_at`: Timestamp when rule was loaded

## Advanced Queries

### Security Analysis

```bash
# Find all hardcoded credential rules (CWE-798)
python3 rule_db.py query "SELECT language, COUNT(*) FROM rules WHERE cwe_references LIKE '%798%' GROUP BY language"

# Find all cryptographic issues (CWE-327, CWE-326, CWE-328)
python3 rule_db.py query "SELECT id, language, message FROM rules WHERE cwe_references REGEXP '32[678]'"

# Rules by severity distribution
python3 rule_db.py query "SELECT severity, COUNT(*) * 100.0 / (SELECT COUNT(*) FROM rules) as percentage FROM rules GROUP BY severity"
```

### Development Insights

```bash
# Most common security issues
python3 rule_db.py query "SELECT cwe_references, COUNT(*) as count FROM rules WHERE cwe_references != '' GROUP BY cwe_references ORDER BY count DESC LIMIT 10"

# Languages with most security rules
python3 rule_db.py query "SELECT language, COUNT(*) as rule_count FROM rules GROUP BY language ORDER BY rule_count DESC"

# Find rules that might have overlapping patterns
python3 rule_db.py query "SELECT language, COUNT(*) as count FROM rules WHERE message LIKE '%hardcoded%' GROUP BY language"
```

## Database Statistics

Current database contains:
- **201 total rules** across 15 programming languages
- **195 warning-level** rules, 3 error-level, 2 info-level
- **Top languages**: Python (48), Java (36), TypeScript (23), Ruby (18)
- **Most common CWEs**: CWE-798 (63 rules), CWE-287 (33 rules), CWE-327 (18 rules)

## Command Reference

- `init [--rules-dir DIR]`: Initialize database and load rules
- `query SQL [--format FORMAT]`: Execute SQL query (formats: table, json, csv)
- `search TERM`: Full-text search across messages and notes
- `stats`: Show database statistics
- `languages`: List available programming languages
- `lang LANGUAGE`: Show rules for specific language

## Tips

1. Use `LIKE '%term%'` for partial string matching in SQL queries
2. The `rules_fts` virtual table enables fast full-text search
3. CWE references are stored as comma-separated strings (e.g., "798,287")
4. Complex ast-grep patterns are stored as JSON in `ast_grep_pattern` column
5. Use `--format json` for programmatic processing of results