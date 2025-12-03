#!/usr/bin/env python3
"""
Check database structure
"""
import sqlite3

def check_db_structure():
    """Check the structure of the SQLite database."""
    try:
        conn = sqlite3.connect('db.sqlite3')
        cursor = conn.cursor()
        
        # Get all tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()
        print("Tables in database:")
        for table in tables:
            print(f"  - {table[0]}")
        
        # Check Users table structure if it exists
        for table in tables:
            table_name = table[0]
            if 'user' in table_name.lower():
                print(f"\nStructure of table '{table_name}':")
                cursor.execute(f"PRAGMA table_info({table_name});")
                columns = cursor.fetchall()
                for col in columns:
                    print(f"  {col[1]} ({col[2]})")
        
        conn.close()
        
    except Exception as e:
        print(f"Error checking database structure: {e}")

if __name__ == '__main__':
    check_db_structure()
    print("Script completed.")