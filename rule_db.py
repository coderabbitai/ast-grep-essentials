#!/usr/bin/env python3
"""
Interactive AST-Grep Rules Database
A SQL-queryable database for ast-grep security rules
"""

import sqlite3
import json
import yaml
import re
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional, Any
import click
from datetime import datetime


class RuleDatabase:
    def __init__(self, db_path: str = "rules.db"):
        self.db_path = db_path
        self.conn = None
        self.init_db()

    def init_db(self):
        """Initialize the database with schema"""
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row  # Enable dict-like access
        
        # Create main rules table
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS rules (
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
            )
        """)
        
        # Create indexes for performance
        indexes = [
            "CREATE INDEX IF NOT EXISTS idx_language ON rules(language)",
            "CREATE INDEX IF NOT EXISTS idx_severity ON rules(severity)",
            "CREATE INDEX IF NOT EXISTS idx_category ON rules(category)",
            "CREATE INDEX IF NOT EXISTS idx_cwe ON rules(cwe_references)"
        ]
        
        for index in indexes:
            self.conn.execute(index)
        
        # Create FTS5 table for full-text search
        self.conn.execute("""
            CREATE VIRTUAL TABLE IF NOT EXISTS rules_fts USING fts5(
                id, message, note, content='rules', content_rowid='rowid'
            )
        """)
        
        self.conn.commit()

    def extract_cwe_references(self, note: str) -> List[str]:
        """Extract CWE references from note field"""
        if not note:
            return []
        
        # Match patterns like [CWE-798], CWE-798, CWE 798
        cwe_pattern = r'\[?CWE[-\s]?(\d+)\]?'
        matches = re.findall(cwe_pattern, note, re.IGNORECASE)
        return list(set(matches))  # Remove duplicates

    def parse_rule_file(self, file_path: Path) -> Optional[Dict[str, Any]]:
        """Parse a single rule YAML file"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                rule_data = yaml.safe_load(f)
            
            if not rule_data or not isinstance(rule_data, dict):
                return None
            
            # Extract metadata from file path
            path_parts = file_path.parts
            language = None
            category = None
            
            # Find language and category from path
            for i, part in enumerate(path_parts):
                if part == 'rules' and i + 1 < len(path_parts):
                    language = path_parts[i + 1]
                    if i + 2 < len(path_parts):
                        category = path_parts[i + 2]
                    break
            
            # Extract CWE references
            cwe_refs = self.extract_cwe_references(rule_data.get('note', ''))
            
            return {
                'id': rule_data.get('id'),
                'language': language or rule_data.get('language', 'unknown'),
                'severity': rule_data.get('severity', 'unknown'),
                'message': rule_data.get('message', ''),
                'note': rule_data.get('note', ''),
                'category': category or 'unknown',
                'file_path': str(file_path),
                'cwe_references': ','.join(cwe_refs) if cwe_refs else '',
                'ast_grep_pattern': json.dumps(rule_data.get('rule', {})),
                'utils_patterns': json.dumps(rule_data.get('utils', {}))
            }
            
        except Exception as e:
            print(f"Error parsing {file_path}: {e}")
            return None

    def load_rules(self, rules_dir: str = "rules"):
        """Load all rules from the rules directory"""
        rules_path = Path(rules_dir)
        if not rules_path.exists():
            print(f"Rules directory {rules_dir} not found")
            return
        
        # Clear existing rules
        self.conn.execute("DELETE FROM rules")
        self.conn.execute("DELETE FROM rules_fts")
        
        loaded_count = 0
        
        # Find all YAML files in rules directory
        for yaml_file in rules_path.rglob("*.yml"):
            rule_data = self.parse_rule_file(yaml_file)
            if rule_data and rule_data['id']:
                try:
                    # Insert into main table
                    self.conn.execute("""
                        INSERT OR REPLACE INTO rules 
                        (id, language, severity, message, note, category, file_path, 
                         cwe_references, ast_grep_pattern, utils_patterns)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        rule_data['id'],
                        rule_data['language'],
                        rule_data['severity'],
                        rule_data['message'],
                        rule_data['note'],
                        rule_data['category'],
                        rule_data['file_path'],
                        rule_data['cwe_references'],
                        rule_data['ast_grep_pattern'],
                        rule_data['utils_patterns']
                    ))
                    
                    # Insert into FTS table
                    self.conn.execute("""
                        INSERT INTO rules_fts (id, message, note)
                        VALUES (?, ?, ?)
                    """, (rule_data['id'], rule_data['message'], rule_data['note']))
                    
                    loaded_count += 1
                    
                except Exception as e:
                    print(f"Error inserting rule {rule_data['id']}: {e}")
        
        self.conn.commit()
        print(f"Loaded {loaded_count} rules into database")

    def query(self, sql: str, params: tuple = ()) -> List[sqlite3.Row]:
        """Execute a SQL query"""
        try:
            if not self.conn:
                print("Database connection not initialized")
                return []
            cursor = self.conn.execute(sql, params)
            return cursor.fetchall()
        except Exception as e:
            print(f"Query error: {e}")
            print(f"SQL: {sql}")
            print(f"Params: {params}")
            return []

    def search(self, term: str) -> List[sqlite3.Row]:
        """Full-text search across messages and notes"""
        return self.query("""
            SELECT r.* FROM rules r
            JOIN rules_fts f ON r.id = f.id
            WHERE rules_fts MATCH ?
            ORDER BY rank
        """, (term,))

    def get_stats(self) -> Dict[str, Any]:
        """Get database statistics"""
        stats = {}
        
        # Total rules
        result = self.query("SELECT COUNT(*) as count FROM rules")
        stats['total_rules'] = result[0]['count'] if result else 0
        
        # Rules by language
        result = self.query("""
            SELECT language, COUNT(*) as count 
            FROM rules 
            GROUP BY language 
            ORDER BY count DESC
        """)
        stats['by_language'] = [(row['language'], row['count']) for row in result]
        
        # Rules by severity
        result = self.query("""
            SELECT severity, COUNT(*) as count 
            FROM rules 
            GROUP BY severity 
            ORDER BY count DESC
        """)
        stats['by_severity'] = [(row['severity'], row['count']) for row in result]
        
        # Rules by category
        result = self.query("""
            SELECT category, COUNT(*) as count 
            FROM rules 
            GROUP BY category 
            ORDER BY count DESC
        """)
        stats['by_category'] = [(row['category'], row['count']) for row in result]
        
        # Top CWE references
        result = self.query("""
            SELECT cwe_references, COUNT(*) as count 
            FROM rules 
            WHERE cwe_references != ''
            GROUP BY cwe_references 
            ORDER BY count DESC
            LIMIT 10
        """)
        stats['top_cwe'] = [(row['cwe_references'], row['count']) for row in result]
        
        return stats

    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()


@click.group()
@click.option('--db', default='rules.db', help='Database file path')
@click.pass_context
def cli(ctx, db):
    """Interactive AST-Grep Rules Database"""
    ctx.ensure_object(dict)
    ctx.obj['db'] = RuleDatabase(db)


@cli.command()
@click.option('--rules-dir', default='rules', help='Rules directory path')
@click.pass_context
def init(ctx, rules_dir):
    """Initialize database and load rules"""
    db = ctx.obj['db']
    print("Initializing database and loading rules...")
    db.load_rules(rules_dir)
    print("Database initialization complete!")


@cli.command()
@click.argument('sql_query')
@click.option('--format', 'output_format', default='table', 
              type=click.Choice(['table', 'json', 'csv']), 
              help='Output format')
@click.pass_context
def query(ctx, sql_query, output_format):
    """Execute SQL query"""
    db = ctx.obj['db']
    results = db.query(sql_query)
    
    if not results:
        print("No results found")
        return
    
    if output_format == 'json':
        data = [dict(row) for row in results]
        print(json.dumps(data, indent=2))
    elif output_format == 'csv':
        import csv
        import io
        output = io.StringIO()
        if results:
            writer = csv.DictWriter(output, fieldnames=results[0].keys())
            writer.writeheader()
            for row in results:
                writer.writerow(dict(row))
        print(output.getvalue())
    else:  # table format
        if results:
            # Print header
            headers = list(results[0].keys())
            print(' | '.join(headers))
            print('-' * (len(' | '.join(headers))))
            
            # Print rows
            for row in results:
                values = [str(row[col])[:50] + '...' if len(str(row[col])) > 50 
                         else str(row[col]) for col in headers]
                print(' | '.join(values))


@cli.command()
@click.argument('search_term')
@click.pass_context
def search(ctx, search_term):
    """Full-text search rules"""
    db = ctx.obj['db']
    results = db.search(search_term)
    
    if not results:
        print(f"No results found for '{search_term}'")
        return
    
    for row in results:
        print(f"\n{row['id']} ({row['language']}) - {row['severity']}")
        print(f"Message: {row['message']}")
        if row['note']:
            note = row['note'][:200] + '...' if len(row['note']) > 200 else row['note']
            print(f"Note: {note}")
        print(f"File: {row['file_path']}")


@cli.command()
@click.pass_context
def stats(ctx):
    """Show database statistics"""
    db = ctx.obj['db']
    stats = db.get_stats()
    
    print(f"Total Rules: {stats['total_rules']}\n")
    
    print("Rules by Language:")
    for lang, count in stats['by_language'].items():
        print(f"  {lang}: {count}")
    
    print("\nRules by Severity:")
    for severity, count in stats['by_severity'].items():
        print(f"  {severity}: {count}")
    
    print("\nRules by Category:")
    for category, count in stats['by_category'].items():
        print(f"  {category}: {count}")
    
    if stats['top_cwe']:
        print("\nTop CWE References:")
        for cwe, count in stats['top_cwe'].items():
            print(f"  CWE-{cwe}: {count}")


@cli.command()
@click.pass_context
def languages(ctx):
    """List available languages"""
    db = ctx.obj['db']
    results = db.query("SELECT DISTINCT language FROM rules ORDER BY language")
    
    print("Available languages:")
    for row in results:
        print(f"  {row['language']}")


@cli.command()
@click.argument('language')
@click.pass_context
def lang(ctx, language):
    """Show rules for specific language"""
    db = ctx.obj['db']
    results = db.query("SELECT id, severity, message FROM rules WHERE language = ? ORDER BY severity, id", (language,))
    
    if not results:
        print(f"No rules found for language: {language}")
        return
    
    print(f"Rules for {language}:")
    for row in results:
        print(f"  {row['id']} ({row['severity']}) - {row['message'][:80]}...")


if __name__ == '__main__':
    cli()