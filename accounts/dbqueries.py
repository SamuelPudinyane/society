import json
import os
import psycopg
from psycopg import errors as pg_errors
from accounts import db
from sqlalchemy import text
from dotenv import load_dotenv
import typing as t
from werkzeug.security import generate_password_hash, check_password_hash
from accounts.utils import unique_security_token

# Load environment variables first, then read Postgres connection details
load_dotenv()
# Postgres connection details are read from env
# PG_HOST, PG_PORT, PG_DB, PG_USER, PG_PASSWORD or DATABASE_URI
PG_HOST = os.getenv("PG_HOST", "localhost")
PG_PORT = os.getenv("PG_PORT", "5432")
PG_DB = os.getenv("PG_DB", "society_master")
PG_USER = os.getenv("PG_USER", "postgres")
PG_PASSWORD = os.getenv("PG_PASSWORD", "malvapudding78*")


# '''
def get_connection():
    """Get a psycopg connection to Postgres."""
    try:
        return psycopg.connect(
            host=PG_HOST,
            port=PG_PORT,
            dbname=PG_DB,
            user=PG_USER,
            password=PG_PASSWORD,
        )
    except Exception as e:
        raise RuntimeError(f"Failed to connect to Postgres: {e}")

# Online
# DB_SERVER = os.getenv("DB_SERVER", "dpg-cudl8flumphs73cpbcj0-a")
# DB_PORT = os.getenv("DB_PORT", "5432")
# DB_NAME = os.getenv("DB_NAME", "randrefinerydb_hdcz")
# DB_USER = os.getenv("DB_USER", "randrefinerydb_hdcz_user")
# DB_PASSWORD = os.getenv("DB_PASSWORD", "NJY9sBdbbw3Sipd0gFGhHFjlLoiWnaaD")



# def get_connection():
#     try:
#         conn =(f"postgresql+psycopg://{DB_USER}:{DB_PASSWORD}@{DB_SERVER}:{DB_PORT}/{DB_NAME}?sslmode=disable")
#         engine = create_engine(conn)
#         connection = engine.connect()
#         print("✅ Database connection successful")
#         return connection
#     except SQLAlchemyError as e:
#         print("❌ Database connection failed!")
#         print(f"Error details: {e}")
#         return None
   


import json



def insert_copies(id_copy, certificate, user_id):
    """
    Inserts a new copy record into the 'copies' table and returns the inserted row as a dictionary.
    """
    try:
        conn = get_connection()
        cursor = conn.cursor()
        
        # Insert the copy record with OUTPUT clause for SQL Server
        cursor.execute(
            """
            INSERT INTO copies (id_copy, certificate, user_id)
            VALUES (%s, %s, %s)
            RETURNING *
            """,
            (id_copy, certificate, user_id),
        )
        
        # Fetch the inserted record
        inserted_row = cursor.fetchone()
        conn.commit()
        
        if inserted_row:
            # Convert to dictionary
            columns = [desc.name for desc in cursor.description]
            return dict(zip(columns, inserted_row))
        
        return None

    except Exception as e:
        print("Error inserting copy:", e)
        return None
        
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

def set_password(password: str) -> str:
    """Hash a plaintext string (password or identifier)."""
    return generate_password_hash(password)

def insertUserIntodb(first_name, last_name, email, contact_number, occupation, gender, date_of_birth, address, postal_code, role, password):
    """
    Inserts a new user into the Users table and returns the inserted row as a dictionary.
    """
    try:
        password_hashed = set_password(password)
        user_id = set_password(email)  # You can replace this with a proper unique ID generator if needed
        
        conn = get_connection()
        cursor = conn.cursor()
        
        # Insert the user with OUTPUT clause for SQL Server
        query = """
                INSERT INTO "Users" (
                user_id, first_name, last_name, email, contact_number,
                occupation, gender, date_of_birth, address, postal_code,
                role, password
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING *
        """

        cursor.execute(
            query,
            (
                user_id, first_name, last_name, email, contact_number,
                occupation, gender, date_of_birth, address, postal_code,
                role, password_hashed,
            ),
        )
        inserted_user = cursor.fetchone()
        conn.commit()
        
        if inserted_user:
            # Convert to dictionary
            columns = [desc.name for desc in cursor.description]
            user_dict = dict(zip(columns, inserted_user))
            return user_dict

        return None

    except Exception as e:
        # Provide clearer feedback for common constraint violations
        if isinstance(e, pg_errors.UniqueViolation):
            print("Error inserting user: duplicate email (unique constraint)")
        else:
            print(f"Error inserting user: {e}")
        print(f"Error type: {type(e).__name__}")
        import traceback
        traceback.print_exc()
        if 'conn' in locals():
            conn.rollback()
        return None
    
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()




def authenticate(email: str, password):
    """
    Authenticates a user based on email and password using pyodbc.

    :param email: User's email.
    :param password: User's plain-text password.
    :return: Dictionary of user data if authenticated, else None.
    """
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM "Users" WHERE email = %s', (email,))
        user_row = cursor.fetchone()

        if user_row:
            # Convert to dictionary
            columns = [desc.name for desc in cursor.description]
            user_data = dict(zip(columns, user_row))

            # Check password
            if check_password_hash(user_data['password'], password):
                return user_data

        return None

    except Exception as e:
        print("Authentication error:", e)
        return None
    
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()



# Deduplicated set_password above; removed duplicate definition.


def insert_user_Token(user_id):
    """
    Creates a new token for a user and inserts it into the user_token table.

    :param user_id: The ID of the user to associate with the token.
    :return: A dictionary representing the inserted token record.
    """
    token = unique_security_token()

    try:
        conn = get_connection()
        cursor = conn.cursor()
        
        # Insert new token using pyodbc
        cursor.execute("""
            INSERT INTO user_token (token, user_id)
            OUTPUT INSERTED.*
            VALUES (?, ?)
        """, (token, user_id))

        inserted_row = cursor.fetchone()
        conn.commit()

        if inserted_row:
            # Convert to dictionary
            columns = [desc[0] for desc in cursor.description]
            return dict(zip(columns, inserted_row))
        
        return None

    except Exception as e:
        if 'conn' in locals():
            conn.rollback()
        print("Error inserting user token:", e)
        return None
        
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()



def check_password(self, password) -> bool:
        
        """
        Checks if the provided password matches the hashed password.

        :param password: The plain-text password to check.
        """
        
        return check_password_hash(self, password)

def send_confirmation(user):
        """
        Sends user's account confirmation email.
        """
        from accounts.email_utils import send_confirmation_mail

        return send_confirmation_mail(user)

def token():
        """
        Verifies whether a security token is valid and not expired.

        :param token: The security token to verify.
        :param raise_exception: If True, raises a 404 error if the token is not found. Defaults to True.

        :return: `True` if the token exists and is not expired, `False` otherwise.
        """
        from accounts.email_utils import send_confirmation_mail
        token=send_confirmation_mail()

        return token


def get_user_by_email(email):
    """
    Retrieves a user by their email.

    :param email: The email of the user to retrieve.
    :return: A dictionary of user columns if found, otherwise an empty dictionary.
    """
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM "Users" WHERE email = %s', (email,))
        user_row = cursor.fetchone()

        if user_row:
            # Convert to dictionary
            columns = [desc.name for desc in cursor.description]
            return dict(zip(columns, user_row))

        return {}

    except Exception as e:
        print("Error fetching user by email:", e)
        return {}
    
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()


def verify_token(token, salt, raise_exception: bool = True):
    """
    Verifies whether a security token is valid and not expired.

    :param token: The security token to verify.
    :param salt: The salt used to hash or generate the token.
    :param raise_exception: If True, raises an exception if the token is not found or expired.
    :return: A dictionary representing the token record if valid, or None if not valid.
    """
    try:
        conn = get_connection()
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT * FROM user_token WHERE token = %s AND salt = %s",
            (token, salt),
        )
        token_row = cursor.fetchone()

        if token_row:
            # Convert to dictionary
            columns = [desc.name for desc in cursor.description]
            token_dict = dict(zip(columns, token_row))
            
            # Check if token is expired (expire = 0 means not expired, expire = 1 means expired)
            if not token_dict.get('expire', True):
                return token_dict

        if raise_exception:
            raise Exception("Token not found or expired")

        return None

    except Exception as e:
        print("Error verifying token:", e)
        if raise_exception:
            raise
        return None
        
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()
    


def get_user_by_id(user_id, raise_exception: bool = False):
    """
    Retrieves a user instance from the database based on their User ID.

    :param user_id: The ID of the user to retrieve.
    :param raise_exception: If True, raises an exception if the user is not found. Defaults to False.
    :return: A dictionary containing user data if found, otherwise None.
    """
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM "Users" WHERE user_id = %s', (user_id,))
        user = cursor.fetchone()

        if user:
            user_dict = dict(zip([column.name for column in cursor.description], user))
            return user_dict

        if raise_exception:
            raise Exception(f"User with ID {user_id} not found.")
        
        return None

    except Exception as e:
        print("Error fetching user by ID:", e)
        if raise_exception:
            raise
        return None
    
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()


def activate_user_and_expire_token(user_id, auth_token):
    """
    Activates the user's account and expires the token.

    :param user_id: The ID of the user whose account will be activated.
    :param auth_token: The token to be expired.
    :return: None
    """
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute('UPDATE "Users" SET active = TRUE WHERE user_id = %s', (user_id,))
        cursor.execute("UPDATE user_token SET expire = TRUE WHERE token = %s", (auth_token,))
        conn.commit()

        print(f"User {user_id} activated and token expired successfully.")

    except Exception as e:
        print(f"Database error: {e}")
        raise Exception("InternalServerError: Unable to activate user and expire token.") from e

    finally:
        if 'cursor' in locals():
            cursor.close()
        conn.close()




def get_users():
    """
    Retrieves all users, including column names and their corresponding entry data.

    :return: A list of dictionaries, each containing user columns and data.
    """
    conn = get_connection()
    try:
        # Execute the query and fetch all results
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM "Users"')
        rows = cursor.fetchall()

        if rows:
            # Get column names from cursor description
            columns = [desc.name for desc in cursor.description]

            # Map each row to a dictionary
            users_data = [dict(zip(columns, row)) for row in rows]
            return users_data

        return []

    except Exception as e:
        print(f"Error fetching users: {e}")
        return []

    finally:
        if 'cursor' in locals():
            cursor.close()
        conn.close()



def reset_password_and_expire_token(user_id: str, new_password: str, auth_token: str):
    """
    Resets the user's password and expires the associated token.

    :param user_id: The ID of the user whose password needs to be reset.
    :param new_password: The new password to set for the user.
    :param auth_token: The token to expire after password reset.
    :return: None
    """
    conn = get_connection()
    try:
        # Update password and expire token using parameterized queries
        cursor = conn.cursor()
        cursor.execute(
            'UPDATE "Users" SET password = %s WHERE user_id = %s',
            (set_password(new_password), user_id),
        )
        cursor.execute(
            "UPDATE user_token SET expire = 1 WHERE token = %s",
            (auth_token,),
        )

        # Commit changes
        conn.commit()
        print(f"Password for user {user_id} has been reset and token expired successfully.")

    except Exception as e:
        print(f"Database error: {e}")
        raise Exception("InternalServerError: Unable to reset password and expire token.")

    finally:
        if 'cursor' in locals():
            cursor.close()
        conn.close()



def update_password(user_id, new_password):
    """
    Updates the password for a given user in the database.

    Args:
        user_id: The ID of the user to update.
        new_password: The new password for the user.

    Returns:
        True if the update was successful, False otherwise.
    """
    conn = get_connection()
    try:
        hashed_password = set_password(new_password)
        cursor = conn.cursor()
        cursor.execute(
            'UPDATE "Users" SET password = %s WHERE user_id = %s',
            (hashed_password, user_id),
        )
        conn.commit()
        return True
    except Exception as error:
        print("Error while updating password:", error)
        return False
    finally:
        if 'cursor' in locals():
            cursor.close()
        conn.close()




def update_user_profile(user_id, bio, avator):
    """
    Updates the bio and avator for a given user in the database.

    Args:
        user_id: The ID of the user to update.
        bio: The new bio for the user.
        avator: The new avator for the user.

    Returns:
        True if the update was successful, False otherwise.
    """
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE user_profile SET bio = %s, avatar = %s WHERE user_id = %s",
            (bio, avator, user_id),
        )
        conn.commit()
        return True
    except Exception as error:
        print("Error while updating user profile:", error)
        return False
    finally:
        if 'cursor' in locals():
            cursor.close()
        conn.close()




def update_user_details(user_id, first_name, last_name, occupation, contact_number, address, postal_code):
    """
    Updates user details (first_name, last_name, occupation, contact_number, address, postal_code) 
    for a given user in the database.

    Args:
        user_id: The ID of the user to update.
        first_name: The new first name of the user.
        last_name: The new last name of the user.
        occupation: The new occupation of the user.
        contact_number: The new contact number of the user.
        address: The new address of the user.
        postal_code: The new postal code of the user.

    Returns:
        True if the update was successful, False otherwise.
    """
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE "Users"
            SET 
                first_name = %s,
                last_name = %s,
                occupation = %s,
                contact_number = %s,
                address = %s,
                postal_code = %s
            WHERE user_id = %s
            """,
            (first_name, last_name, occupation, contact_number, address, postal_code, user_id),
        )
        conn.commit()
        return True
    except Exception as error:
        print("Error while updating user details:", error)
        return False
    finally:
        if 'cursor' in locals():
            cursor.close()
        conn.close()


def get_profile_by_user_id(user_id):
    """
    Retrieves user profile information from the database based on the user_id.

    Args:
        user_id: The ID of the user.

    Returns:
        A dictionary containing the user profile information 
        (user_id, bio, avatar, created_at, updated_at) if found,
        otherwise None.
    """
    conn = get_connection()
    try:
        # Execute the query directly
        cursor = conn.cursor()
        cursor.execute(
            "SELECT user_id, bio, avatar, created_at, updated_at FROM user_profile WHERE user_id = %s",
            (user_id,),
        )
        row = cursor.fetchone()

        if row:
            # Retrieve column names dynamically
            columns = [desc.name for desc in cursor.description]
            # Map row to a dictionary
            profile = dict(zip(columns, row))
           
            return profile

        return None

    except Exception as error:
        print("Error while fetching user profile:", error)
        return None

    finally:
        if 'cursor' in locals():
            cursor.close()
        conn.close()




def activate_user(user_id):
    """
    Activates the user's account and expires all associated tokens.

    :param user_id: The ID of the user whose account will be activated.
    :return: None
    """
    conn = get_connection()
    try:
        # Activate the user
        cursor = conn.cursor()
        cursor.execute('UPDATE "Users" SET active = 1 WHERE user_id = %s', (user_id,))
        cursor.execute("UPDATE user_token SET expire = TRUE WHERE user_id = %s", (user_id,))

        # Commit the transaction
        conn.commit()
        print(f"User {user_id} activated and tokens expired successfully.")

    except Exception as e:
        print(f"Database error: {e}")
        raise Exception("InternalServerError: Unable to activate user and expire token.")

    finally:
        if 'cursor' in locals():
            cursor.close()
        conn.close()



def verify_user(user_id):
    """
    Activates the user's account and returns the updated user row.

    :param user_id: The ID of the user to verify.
    :return: A dictionary representing the updated user row, or None if not found.
    """
    conn = get_connection()
    try:
        # Verify the user
        cursor = conn.cursor()
        cursor.execute(
            'UPDATE "Users" SET verified = TRUE WHERE user_id = %s',
            (user_id,),
        )
        conn.commit()

        # Retrieve the updated user
        cursor.execute('SELECT * FROM "Users" WHERE user_id = %s', (user_id,))
        row = cursor.fetchone()

        if row:
            columns = [desc.name for desc in cursor.description]
            return dict(zip(columns, row))
        return None

    except Exception as e:
        print(f"Database error: {e}")
        raise Exception("InternalServerError: Unable to verify user")

    finally:
        if 'cursor' in locals():
            cursor.close()
        conn.close()




def get_user_tokens_by_user_id(user_id):
    """
    Retrieves all tokens for a given user_id from the user_token table.

    :param user_id: The ID of the user whose tokens are to be retrieved.
    :return: A list of dictionaries representing the user tokens, or an empty list if none.
    """
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT * 
            FROM user_token
            WHERE user_id = %s
            """,
            (user_id,),
        )

        rows = cursor.fetchall()
        columns = [column.name for column in cursor.description]

        return [dict(zip(columns, row)) for row in rows] if rows else []

    except Exception as e:
        print(f"An error occurred while fetching user tokens: {e}")
        return []

    finally:
        if cursor:
            cursor.close()
        conn.close()



def generate_token(salt, user) -> t.AnyStr:
        """
        Generates a new security token for the user.

        :return: The newly created security token.
        """
        
        instance = create_new(salt, user)
        return instance




import uuid

def create_new(salt, user):
    """
    Creates a new token for a user in the user_token table.

    :param salt: The salt for the token.
    :param user: A dictionary containing user details, including 'user_id'.
    :return: The generated token string.
    """
    conn = get_connection()
    try:
        cursor = conn.cursor()
        token = unique_security_token()

        try:
            cursor.execute(
                """
                INSERT INTO user_token (token, salt, expire, user_id)
                VALUES (%s, %s, FALSE, %s)
                RETURNING *
                """,
                (token, salt, user.get('user_id')),
            )
        except Exception as e:
            print("Error inserting token:", e)
            print("Values:", {
                'token': token,
                'salt': salt,
                'user_id': user.get('user_id'),
            })
            raise

        # Fetch the inserted record
        inserted_row = cursor.fetchone()
        if not inserted_row:
            raise Exception("Failed to create token.")

        # Optionally, you can return the full record as a dictionary:
        columns = [col.name for col in cursor.description]
        inserted_record = dict(zip(columns, inserted_row))

        # Commit transaction
        conn.commit()

        # Return only the token string
        return inserted_record['token']

    except Exception as e:
        # Bubble up detailed error after logging above
        raise Exception(f"An error occurred while creating the token: {e}") from e

    finally:
        if cursor:
            cursor.close()
        conn.close()





class ValidationError(Exception):
    pass

def check_if_exists(field_data, field_name, table_name, message=None):
    """
    Checks if the given field value exists in the specified table in the database.

    :param field_data: The value to check (e.g., email).
    :param field_name: The name of the field/column (e.g., email).
    :param table_name: The table in which to check for the field value.
    :param message: The custom error message to raise if the value exists (optional).

    :raises ValidationError: If the value already exists in the table.
    :return: True if the value does not exist.
    """
    conn = get_connection()
    cursor = None
    try:
        cursor = conn.cursor()

        # Build the query safely for column/table names
        query = f"SELECT TOP 1 * FROM {table_name} WHERE {field_name} = ?"

        cursor.execute(query, (field_data,))
        result = cursor.fetchone()

        if result:
            if not message:
                message = f"{field_name} '{field_data}' already exists."
            raise ValidationError(message)

        return True
    finally:
        if cursor:
            cursor.close()
        conn.close()



def fetch_all_tokens():
    """
    Fetches all tokens from the user_token table.

    :return: A list of dictionaries, where each dictionary represents a token record with column names as keys.
    """
    conn = get_connection()
    cursor = None
    try:
        cursor = conn.cursor()

        # SQL query to fetch all tokens
        cursor.execute("SELECT * FROM user_token")

        # Fetch all rows
        rows = cursor.fetchall()

        # Retrieve column names dynamically
        columns = [column.name for column in cursor.description]

        # Convert rows to a list of dictionaries
        tokens = [dict(zip(columns, row)) for row in rows]

        return tokens if tokens else []

    except Exception as e:
        raise Exception("An error occurred while fetching tokens.") from e
    finally:
        if cursor:
            cursor.close()
        conn.close()



def is_token_exists(token: str):
    """
    Check if a token already exists in the user_token table.

    :param token: The token to check for existence.
    :return: The first matching record as a dictionary, or None if not found.
    """
    conn = get_connection()
    cursor = None
    try:
        cursor = conn.cursor()

        # SQL query to check if the token exists
        cursor.execute(
            """
            SELECT *
            FROM user_token
            WHERE token = %s
            LIMIT 1
            """,
            (token,),
        )

        # Fetch the first result
        row = cursor.fetchone()

        if row:
            # Retrieve column names dynamically
            columns = [column.name for column in cursor.description]

            # Convert the row to a dictionary
            return dict(zip(columns, row))

        # Return None if no record is found
        return None

    except Exception as e:
        raise Exception("An error occurred while checking token existence.") from e
    finally:
        if cursor:
            cursor.close()
        conn.close()




from datetime import datetime, timedelta

from datetime import datetime, timedelta

def is_token_expired(token: str, expiry_minutes: int = 15):
    """
    Checks if a token has expired based on its creation time and the expiration period.

    :param token: The token to check.
    :param expiry_minutes: The number of minutes before a token expires.
    :return: True if the token has expired or does not exist, False otherwise.
    """
    conn = get_connection()
    cursor = None
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT created_at, expire
            FROM user_token
            WHERE token = %s
            """,
            (token,),
        )
        row = cursor.fetchone()

        if not row:
            # Token does not exist
            return True

        created_at, expire = row

        # If token is manually marked as expired
        if expire:
            return True

        # Check if token expired based on creation time
        if datetime.utcnow() >= created_at + timedelta(minutes=expiry_minutes):
            return True

        return False

    except Exception as e:
        raise Exception("An error occurred while checking token expiration.") from e
    finally:
        if cursor:
            cursor.close()
        conn.close()



def get_users_and_profiles():
    """
    Retrieves all columns from Users and user_profile tables, joined by user_id.
    Returns a list of dictionaries where keys are unique column names.
    """
    query = """
        SELECT 
            Users.user_id AS user_id,
            Users.first_name AS first_name,
            Users.last_name AS last_name,
            Users.email AS email,
            Users.contact_number AS contact_number,
            Users.occupation AS occupation,
            Users.gender AS gender,
            Users.date_of_birth AS date_of_birth,
            Users.address AS address,
            Users.postal_code AS postal_code,
            Users.role AS role,
            Users.active AS active,
            Users.verified AS verified,
            user_profile.bio AS profile_bio,
            user_profile.avatar AS profile_avatar,
            user_profile.created_at AS profile_created_at,
            user_profile.updated_at AS profile_updated_at
        FROM 
            "Users"
        INNER JOIN 
            user_profile
        ON 
            "Users".user_id = user_profile.user_id;
    """

    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute(query)
        rows = cursor.fetchall()
        columns = [desc[0] for desc in cursor.description]

        return [dict(zip(columns, row)) for row in rows]

    except Exception as e:
        print(f"Error fetching users and profiles: {e}")
        return []

    finally:
        if cursor:
            cursor.close()
        conn.close()


def delete_user_and_profiles(user_id):
    """
    Deletes a user and their associated profile from the Users and user_profile tables.

    Parameters:
        user_id (str): The ID of the user to delete.

    Returns:
        bool: True if the operation is successful, False otherwise.
    """
    user_profile_query = "DELETE FROM user_profile WHERE user_id = ?"
    users_query = 'DELETE FROM "Users" WHERE user_id = %s'

    conn = None
    cursor = None

    try:
        conn = get_connection()
        cursor = conn.cursor()

        # Delete from user_profile first to maintain referential integrity
        cursor.execute(user_profile_query, (user_id,))
        # Delete from Users table
        cursor.execute(users_query, (user_id,))

        conn.commit()
        return True

    except Exception as e:
        if conn:
            conn.rollback()
        print(f"Error deleting user and profiles: {e}")
        return False

    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()



def get_users_with_profiles_by_id(user_id):
    """
    Retrieves a user's details along with their profile based on user_id.
    
    :param user_id: The ID of the user.
    :return: A dictionary containing user and profile data, or None if not found.
    """
    query = """
        SELECT 
            Users.*, 
            user_profile.*
        FROM 
            "Users"
        LEFT JOIN 
            user_profile
        ON 
            "Users".user_id = user_profile.user_id
        WHERE "Users".user_id = %s;
    """
    conn = None
    cursor = None

    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute(query, (user_id,))
        row = cursor.fetchone()

        if row:
            column_names = [desc[0] for desc in cursor.description]
            return dict(zip(column_names, row))
        return None

    except Exception as e:
        print(f"Error fetching user and profile: {e}")
        return None

    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()



def print_all_tables():
    try:
        # Use psycopg to list tables in Postgres
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT tablename
            FROM pg_catalog.pg_tables
            WHERE schemaname = 'public'
            ORDER BY tablename;
            """
        )
        tables = [r[0] for r in cursor.fetchall()]
        print("Tables in database:")
        for t in tables:
            print(f"  - {t}")
    except Exception as e:
        print(f"Error fetching tables: {e}")
    finally:
        try:
            cursor.close(); conn.close()
        except Exception:
            pass