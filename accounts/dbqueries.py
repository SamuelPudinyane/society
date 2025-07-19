import json
import requests
from flask import jsonify
from datetime import datetime, timedelta
import time
import typing as t
from typing import Optional, Union
from dotenv import load_dotenv
from werkzeug.security import (
    check_password_hash,
    generate_password_hash,
)
from accounts.utils import unique_security_token
import os
import pyodbc
load_dotenv()
conn_str = os.getenv("ODBC_CONN_STR")
'''
DRIVER_NAME='SQL SERVER'
SERVER_NAME='APB-JBS02-113L\SQLEXPRESS'
DATABASE_NAME='newx'

connection_string=F"""
    DRIVER={{{DRIVER_NAME}}};
    SERVER={SERVER_NAME};
    DATABASE={DATABASE_NAME};
    Trust_Connection=yes
"""


'''
def get_connection():
    conn = pyodbc.connect(conn_str)
    return conn

import json

def insert_copies(id_copy,certificate,user_id):

    query = """INSERT INTO copies (id_copy,certificate,user_id) 
               OUTPUT INSERTED.* 
               VALUES (?, ?, ?)"""
    
    conn = get_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute(query, (id_copy,certificate,user_id))
        inserted_user = cursor.fetchone()

        # Retrieve column names dynamically
        columns = [column[0] for column in cursor.description]
        
        # Convert inserted_user to a dictionary
        inserted_user_dict = dict(zip(columns, inserted_user))

        #insert_user_Token(user_id)  # Assuming this function handles token creation
        conn.commit()

        # Return the dictionary (as a JSON response in Flask or as a plain dictionary)
        return inserted_user_dict  # or jsonify(inserted_user_dict) if you're using Flask
    except pyodbc.Error as e:
        print('Error: ', e)
    finally:
        conn.close()


def insertUserIntodb(first_name, last_name, email, contact_number, occupation, gender, date_of_birth, address, postal_code, role, password):
    password = set_password(password)
    user_id = set_password(email)  # Assuming user_id is based on email or some other logic
    query = """INSERT INTO Users (user_id, first_name, last_name, email, contact_number, occupation, gender, date_of_birth, address, postal_code, role, password) 
               OUTPUT INSERTED.* 
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,?)"""
    
    conn = get_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute(query, (user_id, first_name, last_name, email, contact_number,occupation, gender, date_of_birth, address, postal_code, role, password))
        inserted_user = cursor.fetchone()

        # Retrieve column names dynamically
        columns = [column[0] for column in cursor.description]
        
        # Convert inserted_user to a dictionary
        inserted_user_dict = dict(zip(columns, inserted_user))

        #insert_user_Token(user_id)  # Assuming this function handles token creation
        conn.commit()

        # Return the dictionary (as a JSON response in Flask or as a plain dictionary)
        return inserted_user_dict  # or jsonify(inserted_user_dict) if you're using Flask
    except pyodbc.Error as e:
        print('Error: ', e)
    finally:
        conn.close()




def authenticate(email: str, password):
    """
    Authenticates a user based on their email and password using raw SQL.
    
    :param email: The email of the user attempting to authenticate.
    :param password: The password of the user attempting to authenticate.
    
    :return: The authenticated user object if credentials are correct, otherwise None.
    """
    conn = get_connection()
    cursor = conn.cursor()
    
    # SQL query to check if the email exists
    cursor.execute("""
        SELECT * FROM Users WHERE email = ? 
    """, (email,))
    
    user = cursor.fetchone()
    
    if user:
        columns = [column[0] for column in cursor.description]
        # Map column names to the corresponding values
        user_data = dict(zip(columns, user))
        
        # Check if the password matches
        if check_password(user_data['password'],password):
            print('re hiso ',user_data['password'])
            return user_data  # Return the dictionary containing user data
        
    return None



def set_password(password):
        """
        Sets the password for the user after hashing it.

        :param password: The plain-text password to hash and set.
        """
        return generate_password_hash(password)


def insert_user_Token(user_id):
    token=unique_security_token()
    query = """INSERT INTO user_token (token,user_id) 
                    OUTPUT INSERTED.*
                    VALUES (?, ?)"""
    conn = get_connection()
    cursor = conn.cursor()
    try:
                cursor.execute(query, (token,user_id))
                inserted_token = cursor.fetchone()
                conn.commit()
                return inserted_token
    except pyodbc.Error as e:
                print('Error: ', e)
    finally:
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
    Retrieves a user by their email, including column names.

    :param email: The email of the user to retrieve.
    :return: A dictionary of user columns if found, otherwise an empty dictionary.
    """
    conn = get_connection()
    cursor = conn.cursor()

    # Execute the query to fetch the user by email
    cursor.execute("""
        SELECT * 
        FROM Users WHERE email = ?
    """, [email])
    
    # Fetch the result
    user = cursor.fetchone()

    if user:
        # Get column names from cursor description
        columns = [column[0] for column in cursor.description]

        # Map column names to the corresponding values
        user_data = dict(zip(columns, user))
        return user_data
    
    return {}


def verify_token(token, salt, raise_exception: bool = True):
    """
    Verifies whether a security token is valid and not expired.

    :param token: The security token to verify.
    :param salt: The salt used to hash or generate the token.
    :param raise_exception: If True, raises an exception if the token is not found or expired.

    :return: A dictionary representing the token record if valid, or None if not valid.
    """
    try:
        # Set up the database connection
        conn = get_connection()
        cursor = conn.cursor()

        # SQL query to retrieve the token from the database
        cursor.execute("""
            SELECT * 
            FROM user_token
            WHERE token = ? AND salt = ?
        """, (token, salt))  # Ensure parameters are passed as a tuple

        # Fetch the result
        token_record = cursor.fetchone()

        if token_record:
            # Retrieve column names dynamically
            columns = [column[0] for column in cursor.description]

            # Convert the token record to a dictionary
            token_dict = dict(zip(columns, token_record))
            print("my token ",token_dict)
            # Check for expiration (assuming 'is_expired' column exists and is boolean)
            if not token_dict.get('expire', True):
                return token_dict

        # Handle token not found or expired case
        if raise_exception:
            raise Exception("Token not found or expired")

        return None
    finally:
        # Ensure the database connection is closed
        conn.close()


def get_user_by_id(user_id, raise_exception: bool = False):
    """
    Retrieves a user instance from the database based on their User ID.

    :param user_id: The ID of the user to retrieve.
    :param raise_exception: If True, raises an exception if the user is not found. Defaults to False.
    :return: A dictionary containing user data if found, otherwise None.
    """
    # Set up the database connection
    conn = get_connection()
    cursor = conn.cursor()
    
    try:
        # SQL query to retrieve the user by user_id
        cursor.execute("""
            SELECT * 
            FROM Users
            WHERE user_id = ?
        """, (user_id,))  # Ensure user_id is passed as a tuple

        # Fetch the result
        user = cursor.fetchone()
        
        if user:
            # Get column names from the cursor description
            columns = [column[0] for column in cursor.description]
            # Combine column names and values into a dictionary
          
            return dict(zip(columns, user))
        
        if raise_exception:
            # Raise an exception if the user is not found
            raise Exception(f"User with ID {user_id} not found.")

        return None
    finally:
        # Ensure the connection is closed
        conn.close()



def activate_user_and_expire_token(user_id, auth_token):
    print(user_id," token ",auth_token)
    """
    Activates the user's account and expires the token.

    :param user_id: The ID of the user whose account will be activated.
    :param auth_token: The token to be expired.
    :return: None
    """
    try:
        # Set up the database connection
        conn = get_connection()
        cursor = conn.cursor()

        # Update the user's account status to active
        cursor.execute("""
            UPDATE Users
            SET active = 1
            WHERE user_id = ?
        """, [user_id])

        # Update the token status to expired
        cursor.execute("""
            UPDATE user_token
            SET expire = 1
            WHERE token = ?
        """, [auth_token])

        # Commit the changes to the database
        conn.commit()

        print(f"User {user_id} activated and token expired.")

    except Exception as e:
        # Handle database errors (you can customize error handling as needed)
        print(f"Database error: {e}")
        raise Exception("InternalServerError: Unable to activate user and expire token.")

    finally:
        # Ensure the database connection is closed
        conn.close()

def get_users():
    """
    Retrieves all users, including column names and their corresponding entry data.

    :return: A list of dictionaries, each containing user columns and data.
    """
    conn = get_connection()
    cursor = conn.cursor()

    # Execute the query to fetch all users
    cursor.execute("""
        SELECT * 
        FROM Users
    """)
    
    # Fetch the results
    users = cursor.fetchall()

    if users:
        # Get column names from cursor description
        columns = [column[0] for column in cursor.description]

        # Map each row to a dictionary of column names and their respective data
        users_data = [dict(zip(columns, user)) for user in users]
        
        return users_data
    
    return []




def reset_password_and_expire_token(user_id: str, new_password: str, auth_token: str):
    """
    Resets the user's password and expires the associated token.

    :param user_id: The ID of the user whose password needs to be reset.
    :param new_password: The new password to set for the user.
    :param auth_token: The token to expire after password reset.
    :return: None
    """
    try:
        # Set up the database connection
        conn = get_connection()
        cursor = conn.cursor()

        # Update the user's password
        cursor.execute("""
            UPDATE Users
            SET password = ?
            WHERE user_id = ?
        """, new_password, user_id)

        # Expire the token
        cursor.execute("""
            UPDATE UserSecurityTokens
            SET expire = 1
            WHERE token = ?
        """, auth_token)

        # Commit the changes to the database
        conn.commit()

        print(f"Password for user {user_id} has been reset and token expired successfully.")

    except Exception as e:
        # Handle any database errors (e.g., connection issues or SQL errors)
        print(f"Database error: {e}")
        raise Exception("InternalServerError: Unable to reset password and expire token.")

    finally:
        # Ensure the database connection is closed
        conn.close()


def update_password(user_id, new_password):
    """
    Updates the password for a given user in the database.

    Args:
        conn: A psycopg2 connection object.
        user_id: The ID of the user to update.
        new_password: The new password for the user.

    Returns:
        True if the update was successful, False otherwise.
    """

    try:
        conn=get_connection()
        cur = conn.cursor()
        hashed_password = generate_password_hash(new_password) 
        cur.execute("UPDATE Users SET password = %s WHERE user_id = %s", (hashed_password, user_id))
        conn.commit()
        return True
    except Exception as error:
        print("Error while updating password:", error)
        return False
    finally:
        if cur:
            cur.close()


def update_user_profile(user_id, bio, avator):
    """
    Updates the bio and avator for a given user in the database.

    Args:
        conn: A psycopg2 connection object.
        user_id: The ID of the user to update.
        bio: The new bio for the user.
        avator: The new avator for the user.

    Returns:
        True if the update was successful, False otherwise.
    """
    conn=get_connection()
    try:
        cur = conn.cursor()
        cur.execute("""
            UPDATE user_profile
            SET bio = %s, avator = %s
            WHERE user_id = %s
        """, (bio, avator, user_id))
        conn.commit()
        return True
    except Exception as error:
        print("Error while updating user profile:", error)
        return False
    finally:
        if cur:
            cur.close()




def update_user_details(user_id, first_name, last_name, occupation, contact_number, address, postal_code):
    """
    Updates user details (first_name, last_name, occupation, contact_number, address, postal_code) 
    for a given user in the database.

    Args:
        conn: A psycopg2 connection object.
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
    conn=get_connection()
    try:
        cur = conn.cursor()
        cur.execute("""
            UPDATE Users 
            SET 
                first_name = %s, 
                last_name = %s, 
                occupation = %s, 
                contact_number = %s, 
                address = %s, 
                postal_code = %s
            WHERE user_id = %s
        """, (first_name, last_name, occupation, contact_number, address, postal_code, user_id))
        conn.commit()
        return True
    except Exception as error:
        print("Error while updating user details:", error)
        return False
    finally:
        if cur:
            cur.close()


def get_profile_by_user_id(user_id):
    """
    Retrieves user profile information from the database based on the user_id.

    Args:
        user_id: The ID of the user.

    Returns:
        A dictionary containing the user profile information 
        (id, user_id, bio, avatar, created_at, updated_at) if found,
        otherwise None.
    """
    conn = get_connection()
    try:
        cur = conn.cursor()
        # Execute the query
        cur.execute("SELECT user_id, bio, avatar, created_at, updated_at FROM user_profile WHERE user_id = ?", (user_id,))
        row = cur.fetchone()

        if row:
            # Retrieve column names dynamically
            columns = [desc[0] for desc in cur.description]
            # Map row to a dictionary
            profile = dict(zip(columns, row))
            print("profile ",profile)
            return profile
        else:
            return None

    except Exception as error:
        print("Error while fetching user profile:", error)
        return None
    finally:
        # Close cursor and connection
        if cur:
            cur.close()
        conn.close()




def activate_user(user_id):
    """
    Activates the user's account and expires the token.

    :param user_id: The ID of the user whose account will be activated.
    :param auth_token: The token to be expired.
    :return: None
    """
    try:
        # Set up the database connection
        conn = get_connection()
        cursor = conn.cursor()

        # Update the user's account status to active
        cursor.execute("""
            UPDATE Users
            SET active = 1
            WHERE user_id = ?
        """, user_id)

        # Update the token status to expired
        cursor.execute("""
            UPDATE user_tokens
            SET expire = 1
            WHERE user_id = ?
        """, user_id)

        # Commit the changes to the database
        conn.commit()

        print(f"User {user_id} activated and token expired successfully.")

    except Exception as e:
        # Handle database errors (you can customize error handling as needed)
        print(f"Database error: {e}")
        raise Exception("InternalServerError: Unable to activate user and expire token.")

    finally:
        # Ensure the database connection is closed
        conn.close()


def verify_user(user_id):
    """
    Activates the user's account, expires the token, and returns the updated row.

    :param user_id: The ID of the user whose account will be activated.
    :return: A dictionary representing the updated row with column names as keys, or None if not found.
    """
    try:
        # Set up the database connection
        conn = get_connection()
        cursor = conn.cursor()

        # Update the user's account status to active
        cursor.execute("""
            UPDATE Users
            SET verified = 1
            WHERE user_id = ?
        """, [user_id])

        # Commit the changes to the database
        conn.commit()

        # Retrieve the updated row
        cursor.execute("""
            SELECT *
            FROM Users
            WHERE user_id = ?
        """, [user_id])

        # Fetch the result
        row = cursor.fetchone()

        # Extract column names dynamically
        column_names = [desc[0] for desc in cursor.description]
        updated_row = dict(zip(column_names, row)) if row else None

        print(f"User {user_id} verification successfully.")
        return updated_row

    except Exception as e:
        # Handle database errors
        print(f"Database error: {e}")
        raise Exception("InternalServerError: Unable to verify user")

    finally:
        # Ensure the database connection is closed
        if conn:
            conn.close()



def get_user_tokens_by_user_id(user_id):
    """
    Retrieves all tokens for a given user_id from the user_token table.

    :param user_id: The ID of the user whose tokens are to be retrieved.
    :return: A list of dictionaries representing the user tokens.
    """
    try:
        # Connect to the database
        conn = get_connection()
        cursor = conn.cursor()

        # Execute the query
        cursor.execute("""
            SELECT *
            FROM user_token
            WHERE user_id = ?
        """, (user_id,))  # Ensure user_id is passed as a tuple

        # Fetch all results
        rows = cursor.fetchall()

        # Get column names
        columns = [column[0] for column in cursor.description]

        # Convert rows to list of dictionaries
        results = [dict(zip(columns, row)) for row in rows]

        # Close the connection
        cursor.close()
        conn.close()
        
        return results

    except Exception as e:
        print(f"An error occurred: {e}")
        return None



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
    :return: A dictionary representing the inserted token record.
    """
    try:
        # Establish database connection
        connection = get_connection()
        cursor = connection.cursor()

        # Generate a unique token
        token = unique_security_token()

        # Insert a new record into the user_token table and return the inserted record
        cursor.execute("""
            INSERT INTO user_token (token, salt, expire, user_id)
            OUTPUT INSERTED.*
            VALUES (?, ?, 0, ?)
        """, (token, salt, user['user_id']))

        # Fetch the inserted record
        inserted_row = cursor.fetchone()

        # Get column names dynamically
        columns = [column[0] for column in cursor.description]

        # Convert the inserted row to a dictionary
        inserted_record = dict(zip(columns, inserted_row))

        # Commit the transaction
        connection.commit()

        # Print and return the inserted record
        return inserted_record['token']
    except Exception as e:
        # Handle any errors
        raise Exception("An error occurred while creating the token.") from e
    finally:
        # Close the connection
        connection.close()





def check_if_exists(field_data,field_name, table_name, message=None):
    """
    Checks if the given field value exists in the specified table in the database.
    
    :param field_data: The value to check (e.g., email).
    :param field_name: The name of the field/column (e.g., email).
    :param table_name: The table in which to check for the field value.
    :param connection_string: The database connection string.
    :param message: The custom error message to raise if the value exists (optional).
    
    :raises: ValidationError if the value already exists in the table.
    """
    email=field_name
    
    # Establish connection to the database
    conn = get_connection()
    cursor = conn.cursor()
    
    # SQL query to check if the value already exists in the field
    query = f"SELECT TOP 1 * FROM {table_name} WHERE email = ?"
    
    # Execute the query with the field_data as parameter
    cursor.execute(query, (field_data,))
    result = cursor.fetchone()

    # Check if the result is not None (i.e., record found)
    if result:
        if not message:
            message = "{} already exists.".format(email)
        raise message
    
    # Close the connection
    cursor.close()
    conn.close()

    # If no record is found, return True indicating the value doesn't exist
    return True


def fetch_all_tokens():
    """
    Fetches all tokens from the user_token table.

    :return: A list of dictionaries, where each dictionary represents a token record with column names as keys.
    """
    try:
        # Establish database connection
        conn = get_connection()
        cursor = conn.cursor()

        # SQL query to fetch all tokens
        cursor.execute("SELECT * FROM user_token")

        # Fetch all rows
        rows = cursor.fetchall()

        # Retrieve column names dynamically
        columns = [column[0] for column in cursor.description]

        # Convert rows to a list of dictionaries
        tokens = [dict(zip(columns, row)) for row in rows]

        return tokens
    except Exception as e:
        # Handle any errors
        raise Exception("An error occurred while fetching tokens.") from e
    finally:
        # Ensure the connection is closed
        conn.close()

def is_token_exists(token: str):
    """
    Check if a token already exists in the user_token table.

    :param token: The token to check for existence.

    :return: The first matching record as a dictionary, or None if not found.
    """
    try:
        # Establish database connection
        conn = get_connection()
        cursor = conn.cursor()

        # SQL query to check if the token exists
        cursor.execute("""
            SELECT TOP 1 *
            FROM user_token
            WHERE token = ?
        """, (token,))

        # Fetch the first result
        row = cursor.fetchone()

        if row:
            # Retrieve column names dynamically
            columns = [column[0] for column in cursor.description]

            # Convert the row to a dictionary
            token_record = dict(zip(columns, row))
            return token_record

        # Return None if no record is found
        return None
    except Exception as e:
        # Handle any errors
        raise Exception("An error occurred while checking token existence.") from e
    finally:
        # Ensure the connection is closed
        conn.close()

from datetime import datetime, timedelta

def is_token_expired(token: str):
    """
    Checks if a token has expired based on its creation time and expiration period.

    :param token: The token to check.
    :return: True if the token has expired, False otherwise.
    """
    try:
        # Establish database connection
        conn = get_connection()
        cursor = conn.cursor()

        # SQL query to fetch token details
        cursor.execute("""
            SELECT created_at, expire
            FROM user_token
            WHERE token = ?
        """, (token,))

        # Fetch the result
        row = cursor.fetchone()

        if row:
            created_at, expire = row

            # If the 'expire' field indicates no expiration, return False
            if not expire:
                expiry_time = created_at + timedelta(minutes=15)
                current_time = datetime.now()

                # Check if the token is still valid
                if current_time < expiry_time:
                    return False

            # Token has expired; optionally, delete it
            cursor.execute("DELETE FROM user_token WHERE token = ?", (token,))
            conn.commit()
            return True

        # If no record is found, consider it expired
        return True
    except Exception as e:
        # Handle any errors
        raise Exception("An error occurred while checking token expiration.") from e
    finally:
        # Ensure the connection is closed
        conn.close()


def get_users_and_profiles():
    """
    Retrieves all columns from Users and Profile tables, joined by user_id.
    """
    query = """
        SELECT 
            Users.*, 
            user_profile.*
        FROM 
            Users
        INNER JOIN 
            user_profile
        ON 
            Users.user_id = user_profile.user_id;
    """
    conn = get_connection()  # Replace with your database connection logic
    cursor = conn.cursor()

    try:
        cursor.execute(query)
        rows = cursor.fetchall()
        column_names = [desc[0] for desc in cursor.description]  # Fetch column names

        # Map the rows to dictionaries
        results = [dict(zip(column_names, row)) for row in rows]
        return results

    except Exception as e:
        print(f"Error fetching users and profiles: {e}")
        return []
    
    finally:
        if conn:  # Ensure the connection is closed even if an error occurs
            conn.close()

def delete_user_and_profiles(user_id):
    """
    Deletes a user and their associated profiles from the Users and user_profile tables.

    Parameters:
        user_id (int): The ID of the user to delete.

    Returns:
        bool: True if the operation is successful, False otherwise.
    """
    # Query to delete from user_profile and Users tables
    user_profile_query = "DELETE FROM user_profile WHERE user_id = ?"
    users_query = "DELETE FROM Users WHERE user_id = ?"

    try:
        # Establish database connection
        conn = get_connection()  # Replace with your database connection logic
        cursor = conn.cursor()

        # Delete from user_profile table first to maintain referential integrity
        cursor.execute(user_profile_query, (user_id,))

        # Then delete from Users table
        cursor.execute(users_query, (user_id,))

        # Commit the transaction
        conn.commit()
        return True

    except Exception as e:
        print(f"Error deleting user and profiles: {e}")
        return False

    finally:
        # Ensure the connection is closed
        if conn:
            conn.close()


def get_users_with_profiles_by_id(id):
    """
    Retrieves all columns from Users and Profile tables, joined by user_id.
    """
    query = """
        SELECT 
            Users.*, 
            user_profile.*
        FROM 
            Users
         LEFT JOIN 
            user_profile
        ON 
            Users.user_id = user_profile.user_id WHERE Users.User_id=?;
    """
    conn = get_connection()  # Replace with your database connection logic
    cursor = conn.cursor()

    try:
        cursor.execute(query,[id])
        rows = cursor.fetchall()
        column_names = [desc[0] for desc in cursor.description]  # Fetch column names

        # Map the rows to dictionaries
        results = [dict(zip(column_names, row)) for row in rows]
        return results

    except Exception as e:
        print(f"Error fetching users and profiles: {e}")
        return []
    
    finally:
        if conn:  # Ensure the connection is closed even if an error occurs
            conn.close()

