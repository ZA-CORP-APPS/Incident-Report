#!/usr/bin/env python3
"""
Incident Type Migration Script
==============================
This script safely adds the IncidentType table and seeds default types.
Run this on your production server before restarting the application.

Usage:
    cd /home/lulo/Incident-Report
    source venv/bin/activate
    python update-incident-types.py

This script is safe to run multiple times - it will not duplicate data.
"""

import os
import sys
import sqlite3
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'instance', 'incidents.db')

def main():
    print("=" * 60)
    print("Incident Type Migration Script")
    print("=" * 60)
    print()
    
    if not os.path.exists(DB_PATH):
        print(f"ERROR: Database not found at {DB_PATH}")
        print("Please run this script from the application directory.")
        sys.exit(1)
    
    print(f"Database: {DB_PATH}")
    print()
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    try:
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='incident_type'")
        table_exists = cursor.fetchone() is not None
        
        if table_exists:
            print("[OK] IncidentType table already exists")
        else:
            print("[CREATING] IncidentType table...")
            cursor.execute("""
                CREATE TABLE incident_type (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name VARCHAR(50) UNIQUE NOT NULL,
                    color VARCHAR(20) DEFAULT 'primary',
                    icon VARCHAR(10) DEFAULT '',
                    is_active BOOLEAN DEFAULT 1,
                    display_order INTEGER DEFAULT 0,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            print("[OK] IncidentType table created")
        
        defaults = [
            {'name': 'Security', 'color': 'primary', 'icon': '', 'display_order': 1},
            {'name': 'Safety', 'color': 'warning', 'icon': '', 'display_order': 2}
        ]
        
        for item in defaults:
            cursor.execute("SELECT id FROM incident_type WHERE name = ?", (item['name'],))
            if cursor.fetchone():
                print(f"[OK] '{item['name']}' type already exists")
            else:
                cursor.execute("""
                    INSERT INTO incident_type (name, color, icon, display_order, is_active)
                    VALUES (?, ?, ?, ?, 1)
                """, (item['name'], item['color'], item['icon'], item['display_order']))
                print(f"[CREATED] '{item['name']}' type added")
        
        conn.commit()
        
        print()
        print("-" * 60)
        print("Current incident types:")
        print("-" * 60)
        cursor.execute("SELECT id, name, color, icon, is_active, display_order FROM incident_type ORDER BY display_order")
        rows = cursor.fetchall()
        for row in rows:
            status = "Active" if row[4] else "Inactive"
            icon = row[3] if row[3] else "(no icon)"
            print(f"  ID: {row[0]}, Name: {row[1]}, Color: {row[2]}, Icon: {icon}, Status: {status}, Order: {row[5]}")
        
        print()
        print("=" * 60)
        print("Migration completed successfully!")
        print("=" * 60)
        print()
        print("Next steps:")
        print("  1. Restart the application: sudo systemctl restart incident-log")
        print("  2. Log in as admin")
        print("  3. Go to Admin menu -> Incident Types to manage types")
        print()
        
    except sqlite3.Error as e:
        print(f"ERROR: Database error: {e}")
        conn.rollback()
        sys.exit(1)
    finally:
        conn.close()


if __name__ == '__main__':
    main()
