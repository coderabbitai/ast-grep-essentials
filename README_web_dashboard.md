# AST-Grep Rules Web Dashboard

A comprehensive web-based dashboard for exploring and analyzing AST-Grep security rules with interactive visualizations, SQL querying, and coverage analysis.

## Features

### 🎯 Dashboard Overview
- **Statistics Cards**: Total rules, languages, severity levels, CWE categories
- **Interactive Charts**: Language distribution (doughnut chart) and severity breakdown (bar chart)
- **Top Languages Table**: Rules count with percentage progress bars
- **Top CWE Categories**: Most common security weaknesses with descriptions
- **Quick Actions**: Direct links to browse rules, query data, and analyze coverage

### 🔍 Rules Browser
- **Advanced Filtering**: Filter by language, severity, and search terms
- **Paginated Results**: Efficient browsing of large rule sets
- **Rule Cards**: Clean cards showing rule ID, language, severity, and message preview
- **Rule Details**: Click any rule for detailed view with AST-grep patterns

### 📊 SQL Query Interface
- **Custom Queries**: Execute arbitrary SQL queries against the rules database
- **Multiple Formats**: Results in table, JSON, or CSV format
- **Sample Queries**: Pre-built queries for common analysis tasks
- **Schema Reference**: Complete database schema documentation
- **Query History**: Navigate previous queries easily

### 📈 Coverage Analysis
- **Language Coverage**: Horizontal bar chart showing rules per language
- **CWE Distribution**: Doughnut chart of security weakness coverage
- **Coverage Matrix**: Language vs CWE heat map showing rule distribution
- **Gap Analysis**: Automated detection of coverage gaps with recommendations
- **Detailed Tables**: Comprehensive breakdown of language and security coverage

## Installation & Setup

### Prerequisites
```bash
pip install Flask click PyYAML
```

### Quick Start
```bash
# 1. Initialize the database
python3 rule_db.py init

# 2. Start the web dashboard
python3 web_dashboard.py

# 3. Open browser to http://localhost:5000
```

## Dashboard Pages

### 1. Main Dashboard (`/`)
- Overview statistics and charts
- Quick navigation to other features
- High-level insights into rule coverage

### 2. Rules Browser (`/rules`)
- Browse all rules with filtering
- Search functionality
- Paginated results
- Rule detail modal

### 3. SQL Query Interface (`/query`)
- Execute custom SQL queries
- Sample queries for common tasks
- Multiple output formats
- Database schema reference

### 4. Coverage Analysis (`/coverage`)
- Language coverage charts
- CWE category analysis
- Coverage matrix visualization
- Gap analysis and recommendations

### 5. Rule Details (`/rule/<rule_id>`)
- Complete rule information
- AST-grep pattern display
- Utility patterns
- Related rules suggestions

## API Endpoints

### Statistics
- `GET /api/stats` - Dashboard statistics
- `GET /api/coverage` - Coverage analysis data

### Rules
- `GET /api/rules` - Paginated rules with filtering
  - Parameters: `page`, `per_page`, `language`, `severity`, `search`

### Query & Search
- `POST /api/query` - Execute SQL queries
  - Body: `{"sql": "SELECT * FROM rules LIMIT 10"}`
- `GET /api/search` - Full-text search
  - Parameters: `q` (search term)

## Sample Queries

### Basic Analytics
```sql
-- Rules by language
SELECT language, COUNT(*) as count 
FROM rules 
GROUP BY language 
ORDER BY count DESC;

-- Security coverage by CWE
SELECT cwe_references, COUNT(*) as count 
FROM rules 
WHERE cwe_references != '' 
GROUP BY cwe_references 
ORDER BY count DESC;

-- Severity distribution
SELECT severity, COUNT(*) as count 
FROM rules 
GROUP BY severity;
```

### Advanced Analysis
```sql
-- Languages with JWT-related rules
SELECT language, COUNT(*) as jwt_rules 
FROM rules 
WHERE message LIKE '%JWT%' OR note LIKE '%JWT%' 
GROUP BY language;

-- Average rule complexity by language
SELECT language, 
       AVG(LENGTH(ast_grep_pattern)) as avg_pattern_size,
       AVG(LENGTH(message)) as avg_message_length
FROM rules 
GROUP BY language 
ORDER BY avg_pattern_size DESC;

-- Find hardcoded credential rules by language
SELECT language, COUNT(*) as hardcoded_rules 
FROM rules 
WHERE cwe_references LIKE '%798%' 
GROUP BY language 
ORDER BY hardcoded_rules DESC;
```

## Coverage Analysis Features

### Language Coverage
- Rules count per language
- CWE categories covered per language
- Relative coverage percentages
- Visual distribution charts

### Security Coverage
- CWE category distribution
- Critical vulnerability coverage
- Coverage gaps identification
- Recommendations for improvement

### Gap Analysis
Automatically identifies:
- Languages with low rule counts (< 5 rules)
- CWE categories with minimal coverage (< 3 rules)
- Missing critical CWE categories (XSS, SQLi, etc.)
- Provides actionable recommendations

## Technology Stack

- **Backend**: Flask (Python web framework)
- **Database**: SQLite with FTS5 full-text search
- **Frontend**: Bootstrap 5, Chart.js
- **Charts**: Interactive charts with Chart.js
- **Icons**: Font Awesome 6
- **Data**: YAML parsing with PyYAML

## Database Schema

```sql
CREATE TABLE rules (
    id TEXT PRIMARY KEY,
    language TEXT NOT NULL,
    severity TEXT NOT NULL,
    message TEXT NOT NULL,
    note TEXT,
    category TEXT,
    file_path TEXT NOT NULL,
    cwe_references TEXT,
    ast_grep_pattern TEXT,
    utils_patterns TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Full-text search table
CREATE VIRTUAL TABLE rules_fts USING fts5(
    id, message, note, content='rules'
);
```

## Usage Examples

### Finding Security Patterns
```bash
# Browse all hardcoded secret rules
http://localhost:5000/rules?search=hardcoded

# Query JWT vulnerabilities across languages
http://localhost:5000/query?sql=SELECT language, COUNT(*) FROM rules WHERE message LIKE '%JWT%' GROUP BY language

# Analyze Python security coverage
http://localhost:5000/coverage
```

### API Usage
```bash
# Get dashboard statistics
curl http://localhost:5000/api/stats

# Search for specific patterns
curl "http://localhost:5000/api/search?q=hardcoded+secret"

# Execute custom query
curl -X POST http://localhost:5000/api/query \
  -H "Content-Type: application/json" \
  -d '{"sql": "SELECT * FROM rules WHERE language = \"python\" LIMIT 5"}'
```

## Production Deployment

For production use:
```bash
# Install production WSGI server
pip install gunicorn

# Run with Gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 web_dashboard:app

# Or use waitress
pip install waitress
waitress-serve --host=0.0.0.0 --port=5000 web_dashboard:app
```

## Development

The dashboard runs in debug mode by default. For development:
- Templates auto-reload on changes
- Database is auto-initialized if missing
- Detailed error messages in browser
- Live reloading enabled

## Contributing

The web dashboard complements the CLI tool (`rule_db.py`) and provides:
- Visual insights into rule distribution
- Interactive exploration capabilities
- Advanced querying with results visualization
- Coverage analysis for identifying gaps

Both CLI and web interfaces share the same database and provide different ways to interact with the AST-Grep rules collection.