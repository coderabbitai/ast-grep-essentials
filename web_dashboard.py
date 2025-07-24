#!/usr/bin/env python3
"""
AST-Grep Rules Web Dashboard
Interactive web interface for exploring and analyzing ast-grep security rules
"""

from flask import Flask, render_template, request, jsonify, send_from_directory
import json
import sqlite3
from pathlib import Path
from rule_db import RuleDatabase
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'ast-grep-rules-dashboard'

# Initialize database with absolute path
import os
db_path = os.path.abspath("rules.db")
db = RuleDatabase(db_path)

@app.route('/')
def dashboard():
    """Main dashboard view"""
    stats = db.get_stats()
    return render_template('dashboard.html', stats=stats)

@app.route('/api/stats')
def api_stats():
    """API endpoint for dashboard statistics"""
    try:
        print(f"Current working directory: {os.getcwd()}")
        print(f"Database path: {db.db_path}")
        print(f"Database file exists: {os.path.exists(db.db_path)}")
        print(f"Database connection: {db.conn}")
        
        # Test a direct query
        test_result = db.query("SELECT COUNT(*) as count FROM rules")
        print(f"Direct query result: {test_result}")
        
        stats = db.get_stats()
        print(f"Stats retrieved: {stats}")
        return jsonify(stats)
    except Exception as e:
        print(f"Error in api_stats: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/api/rules')
def api_rules():
    """API endpoint to get rules with pagination and filtering"""
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 50))
    language = request.args.get('language', '')
    severity = request.args.get('severity', '')
    search = request.args.get('search', '')
    
    # Build WHERE clause
    where_conditions = []
    params = []
    
    if language:
        where_conditions.append("language = ?")
        params.append(language)
    
    if severity:
        where_conditions.append("severity = ?")
        params.append(severity)
    
    if search:
        where_conditions.append("(message LIKE ? OR note LIKE ? OR id LIKE ?)")
        params.extend([f"%{search}%", f"%{search}%", f"%{search}%"])
    
    where_clause = ""
    if where_conditions:
        where_clause = "WHERE " + " AND ".join(where_conditions)
    
    # Get total count
    count_query = f"SELECT COUNT(*) as total FROM rules {where_clause}"
    count_result = db.query(count_query, tuple(params))
    total = count_result[0]['total'] if count_result else 0
    
    # Get paginated results
    offset = (page - 1) * per_page
    query = f"""
        SELECT id, language, severity, message, note, cwe_references, file_path
        FROM rules {where_clause}
        ORDER BY language, id
        LIMIT ? OFFSET ?
    """
    params.extend([per_page, offset])
    
    rules = db.query(query, tuple(params))
    
    return jsonify({
        'rules': [dict(rule) for rule in rules],
        'total': total,
        'page': page,
        'per_page': per_page,
        'total_pages': (total + per_page - 1) // per_page
    })

@app.route('/api/query', methods=['POST'])
def api_query():
    """API endpoint for custom SQL queries"""
    data = request.get_json()
    sql = data.get('sql', '')
    
    if not sql.strip():
        return jsonify({'error': 'SQL query is required'}), 400
    
    # Basic SQL injection protection - only allow SELECT statements
    if not sql.strip().upper().startswith('SELECT'):
        return jsonify({'error': 'Only SELECT queries are allowed'}), 400
    
    try:
        results = db.query(sql)
        return jsonify({
            'success': True,
            'data': [dict(row) for row in results],
            'count': len(results)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/search')
def api_search():
    """API endpoint for full-text search"""
    term = request.args.get('q', '')
    if not term:
        return jsonify({'results': []})
    
    results = db.search(term)
    return jsonify({
        'results': [dict(row) for row in results],
        'count': len(results)
    })

@app.route('/api/coverage')
def api_coverage():
    """API endpoint for coverage analysis"""
    try:
        # Language coverage
        lang_coverage = db.query("""
            SELECT language, 
                   COUNT(*) as rule_count,
                   COUNT(DISTINCT CASE WHEN cwe_references != '' THEN cwe_references END) as cwe_count
            FROM rules 
            GROUP BY language 
            ORDER BY rule_count DESC
        """)
        
        # CWE coverage
        cwe_coverage = db.query("""
            SELECT cwe_references, COUNT(*) as count
            FROM rules 
            WHERE cwe_references != ''
            GROUP BY cwe_references 
            ORDER BY count DESC
            LIMIT 15
        """)
        
        # Severity distribution
        severity_dist = db.query("""
            SELECT severity, COUNT(*) as count
            FROM rules
            GROUP BY severity
            ORDER BY count DESC
        """)
        
        return jsonify({
            'language_coverage': [dict(row) for row in lang_coverage] if lang_coverage else [],
            'cwe_coverage': [dict(row) for row in cwe_coverage] if cwe_coverage else [],
            'severity_distribution': [dict(row) for row in severity_dist] if severity_dist else []
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/rules')
def rules_page():
    """Rules browser page"""
    return render_template('rules.html')

@app.route('/query')
def query_page():
    """SQL query interface page"""
    return render_template('query.html')

@app.route('/coverage')
def coverage_page():
    """Coverage analysis page"""
    return render_template('coverage.html')

@app.route('/rule/<rule_id>')
def rule_detail(rule_id):
    """Rule detail page"""
    rule = db.query("SELECT * FROM rules WHERE id = ?", (rule_id,))
    if not rule:
        return "Rule not found", 404
    
    rule_data = dict(rule[0])
    
    # Parse JSON fields
    try:
        rule_data['ast_grep_pattern'] = json.loads(rule_data['ast_grep_pattern']) if rule_data['ast_grep_pattern'] else {}
        rule_data['utils_patterns'] = json.loads(rule_data['utils_patterns']) if rule_data['utils_patterns'] else {}
    except:
        pass
    
    return render_template('rule_detail.html', rule=rule_data)

if __name__ == '__main__':
    # Ensure templates directory exists
    os.makedirs('templates', exist_ok=True)
    os.makedirs('static', exist_ok=True)
    
    # Initialize database if it doesn't exist or is empty
    if not os.path.exists('rules.db'):
        print("Database file not found. Initializing database...")
        db.load_rules()
        print("Database initialized!")
    else:
        # Check if database has data
        try:
            result = db.query("SELECT COUNT(*) as count FROM rules")
            if not result or result[0]['count'] == 0:
                print("Database is empty. Loading rules...")
                db.load_rules()
                print("Rules loaded!")
            else:
                print(f"Database loaded with {result[0]['count']} rules")
        except Exception as e:
            print(f"Error checking database: {e}")
            print("Reinitializing database...")
            db.load_rules()
    
    app.run(debug=True, host='0.0.0.0', port=5000)