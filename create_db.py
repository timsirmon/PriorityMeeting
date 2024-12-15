# create_db.py
from app import app, db
import os
import sqlite3

def init_db():
    # Get absolute path for database
    base_dir = os.path.abspath(os.path.dirname(__file__))
    db_path = os.path.join(base_dir, 'topics.db')
    
    # Remove existing database
    if os.path.exists(db_path):
        os.remove(db_path)
        print(f"Removed existing database at {db_path}")
    
    # Update app configuration with absolute path
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
    
    with app.app_context():
        try:
            print(f"Creating database at {db_path}")
            db.create_all()
            
            # Verify tables were created using raw SQLite
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # Get list of tables
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = cursor.fetchall()
            
            print("\nVerifying tables:")
            for table in tables:
                print(f"- {table[0]}")
                # Get table schema
                cursor.execute(f"SELECT sql FROM sqlite_master WHERE type='table' AND name='{table[0]}';")
                schema = cursor.fetchone()
                print(f"Schema: {schema[0]}\n")
            
            conn.close()
            return True
            
        except Exception as e:
            print(f"Error creating database: {str(e)}")
            return False

if __name__ == '__main__':
    if init_db():
        print("Database initialization complete!")
    else:
        print("Database initialization failed!")
