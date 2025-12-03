#!/usr/bin/env python3
"""
Database initialization script
"""
import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from accounts import create_app, db

def init_database():
    """Initialize the database with required tables."""
    app = create_app('development')
    
    with app.app_context():
        try:
            # Create all tables
            db.create_all()
            print("Database tables created successfully!")
            
            # Check if tables exist
            inspector = db.inspect(db.engine)
            tables = inspector.get_table_names()
            print(f"Available tables: {tables}")
            
        except Exception as e:
            print(f"Error creating database tables: {e}")
            import traceback
            traceback.print_exc()

if __name__ == '__main__':
    init_database()