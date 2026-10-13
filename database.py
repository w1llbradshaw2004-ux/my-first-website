
import os

import psycopg
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash


# Load environment variables from .env
load_dotenv()


def get_postgres_connection():
    """Connect to the Supabase PostgreSQL database."""

    database_url = os.environ["DATABASE_URL"]

    return psycopg.connect(
        database_url,
        sslmode="require",
        connect_timeout=10
    )


def create_postgres_user(username, password, role="user"):
    """Create a new user with a securely hashed password."""

    password_hash = generate_password_hash(password)

    with get_postgres_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute("""
                INSERT INTO public.users (username, password_hash, role)
                VALUES (%s, %s, %s)
            """, (username, password_hash, role))

    print(f"User '{username}' created successfully!")


def get_postgres_user(username):
    """Retrieve a user by username."""

    with get_postgres_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT id, username, password_hash, role
                FROM public.users
                WHERE username = %s
            """, (username,))

            user = cursor.fetchone()

    return user
