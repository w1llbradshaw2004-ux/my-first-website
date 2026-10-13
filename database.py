
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



def get_postgres_user_by_id(user_id):
    """Find a user by their unique database ID."""

    with get_postgres_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT id, username, password_hash, role
                FROM public.users
                WHERE id = %s
            """, (user_id,))

            return cursor.fetchone()


def get_all_users():
    """Retrieve usernames and roles for the admin dashboard."""

    with get_postgres_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT id, username, role
                FROM public.users
                ORDER BY id
            """)

            return cursor.fetchall()


def create_managed_user(username, password):
    """Create a regular user. Return False if the name exists."""

    password_hash = generate_password_hash(password)

    with get_postgres_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute("""
                INSERT INTO public.users
                    (username, password_hash, role)
                VALUES (%s, %s, 'user')
                ON CONFLICT (username) DO NOTHING
                RETURNING id
            """, (username, password_hash))

            return cursor.fetchone() is not None



def send_message(user_id, content):
    """Save a message to PostgreSQL."""

    content = content.strip()

    if not 1 <= len(content) <= 1000:
        raise ValueError("Messages must contain 1-1000 characters.")

    with get_postgres_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute("""
                INSERT INTO public.messages (user_id, content)
                VALUES (%s, %s)
                RETURNING id
            """, (user_id, content))

            message_id = cursor.fetchone()[0]

    return message_id



def get_messages():
    """Retrieve the latest 100 unexpired messages."""

    with get_postgres_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT
                    messages.id,
                    users.username,
                    messages.content,
                    messages.created_at
                FROM public.messages AS messages
                JOIN public.users AS users
                    ON messages.user_id = users.id
                WHERE messages.expires_at > NOW()
                ORDER BY messages.created_at DESC, messages.id DESC
                LIMIT 100
            """)

            messages = cursor.fetchall()

    return list(reversed(messages))



def delete_message(message_id):
    """Permanently delete a message by its ID."""

    with get_postgres_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute("""
                DELETE FROM public.messages
                WHERE id = %s
                RETURNING id
            """, (message_id,))

            deleted = cursor.fetchone()

    return deleted is not None
