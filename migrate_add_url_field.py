#!/usr/bin/env python3
"""
Миграция для добавления поля url в таблицу secrets
"""
import os
from sqlalchemy import create_engine, text
from app import create_app, db
from models import Secret

def migrate():
    """Добавить колонку url к таблице secrets"""
    app = create_app()
    
    with app.app_context():
        # Получить тип БД из конфигурации
        db_url = app.config['SQLALCHEMY_DATABASE_URI']
        
        try:
            # Проверить, существует ли уже колонка
            inspector = db.inspect(db.engine)
            columns = [col['name'] for col in inspector.get_columns('secrets')]
            
            if 'url' in columns:
                print("✓ Колонка 'url' уже существует в таблице 'secrets'")
                return
            
            # Добавить колонку
            if 'sqlite' in db_url.lower():
                sql = 'ALTER TABLE secrets ADD COLUMN url VARCHAR(500) NULL'
            elif 'postgres' in db_url.lower():
                sql = 'ALTER TABLE secrets ADD COLUMN url VARCHAR(500) NULL'
            elif 'mysql' in db_url.lower():
                sql = 'ALTER TABLE secrets ADD COLUMN url VARCHAR(500) NULL'
            else:
                raise ValueError(f"Неизвестная БД: {db_url}")
            
            with db.engine.connect() as conn:
                conn.execute(text(sql))
                conn.commit()
            
            print(f"✓ Колонка 'url' успешно добавлена")
            
        except Exception as e:
            print(f"✗ Ошибка при добавлении колонки: {e}")
            raise

if __name__ == '__main__':
    migrate()
