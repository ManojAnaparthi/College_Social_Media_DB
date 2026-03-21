import os
from typing import Any

import pymysql
from pymysql.cursors import DictCursor

# Database configuration - in a real app, use environment variables
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_USER = os.getenv("DB_USER", "root")
DB_PASSWORD = os.getenv("DB_PASSWORD", "password")
DB_NAME = os.getenv("DB_NAME", "college_social_media")


class DatabaseQueryError(Exception):
    """Raised when a database operation cannot be completed."""

def get_db_connection():
    """
    Establishes and returns a connection to the local MySQL database.
    Uses DictCursor so results are returned as dictionaries instead of tuples.
    """
    connection = pymysql.connect(
        host=DB_HOST,
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        cursorclass=DictCursor,
        autocommit=True  # Automatically commit transactions for CRUD operations
    )
    return connection

def execute_query(query, params=None, fetchall=False, fetchone=False, audit_context: dict[str, Any] | None = None):
    """
    Helper function to safely execute SQL queries.
    """
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            if audit_context is not None:
                cursor.execute(
                    """
                    SET
                        @api_authorized = %s,
                        @api_actor_id = %s,
                        @api_action = %s,
                        @api_endpoint = %s,
                        @api_method = %s
                    """,
                    (
                        1,
                        audit_context.get("actor_id"),
                        audit_context.get("action"),
                        audit_context.get("endpoint"),
                        audit_context.get("method"),
                    ),
                )
            cursor.execute(query, params)
            if fetchall:
                return cursor.fetchall()
            if fetchone:
                return cursor.fetchone()
            return cursor.lastrowid
    except pymysql.MySQLError as exc:
        raise DatabaseQueryError("Database operation failed") from exc
    finally:
        if conn is not None:
            conn.close()
