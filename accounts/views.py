from flask import abort, render_template, request, redirect, url_for, flash,session,jsonify
from http import HTTPStatus
import requests
from werkzeug.exceptions import InternalServerError
from flask import Blueprint, Response
from flask_login import (
        current_user,
        login_required,
        login_user,
        logout_user
    )
import base64
from accounts.decorators import authentication_redirect
from accounts.email_utils import (
    send_reset_password,send_volunteer_thank_you_email,send_documents_email
)
import gzip
from werkzeug.utils import secure_filename
from accounts.forms import (
        RegisterForm, 
        LoginForm, 
        ForgotPasswordForm,
        ResetPasswordForm,
        ChangePasswordForm,
        EditUserProfileForm
    )
from flask import Flask,current_app
from datetime import datetime, timedelta
import re
import os
import shutil
import json
import urllib.parse
from flask_cors import CORS,cross_origin
from accounts.dbqueries import (insertUserIntodb,authenticate,get_user_by_email,verify_token,get_user_by_id,activate_user_and_expire_token,
                                get_users,reset_password_and_expire_token,check_password,update_password,update_user_details,update_user_profile,
                                get_profile_by_user_id,activate_user,send_confirmation,verify_user,get_users_and_profiles,get_users_with_profiles_by_id,
                                delete_user_and_profiles,insert_copies)
"""
This accounts blueprint defines routes and templates related to user management
within our application.
"""
from config import (
    UPLOAD_FOLDER,
    UPLOAD_FOLDER_SUPPORTING_DOCUMENTS,
   
)
accounts = Blueprint('accounts', __name__, template_folder='templates')
app = Flask(__name__, static_folder='static') 
CORS(app)
@accounts.route('/register', methods=['GET', 'POST'])
def register() -> Response:
    
    """
    Handling user registration.
    If the user is already authenticated, they are redirected to the index page.

    This view handles both GET and POST requests:
    - GET: Renders the registration form and template.
    - POST: Processes the registration form, creates a new user, and sends a confirmation email.

    :return: Renders the registration template on GET request
    or redirects to login after successful registration.
    """
    form = RegisterForm()
    
    if form.validate_on_submit():
                
            first_name = form.data.get('first_name')
            last_name = form.data.get('last_name')
            email=form.data.get('email')
            date_of_birth = form.data.get('date_of_birth')
            gender=form.data.get('gender')
            occupation=form.data.get('occupation')
            contact_number=form.data.get('contact_number')
            address=form.data.get('address')
            postal_code=form.data.get('postal_code') 
            role=form.data.get('role')
            password=form.data.get('password')
           
            
            
            id_copy_filename = None
            certificates_filename = None
            if form.id_copy.data:
                id_copy_filename = secure_filename(form.id_copy.data)
                id_copy_destination = os.path.join(
                    current_app.config["UPLOAD_FOLDER_SUPPORTING_DOCUMENTS"],
                    id_copy_filename,
                )
                os.makedirs(os.path.dirname(id_copy_destination), exist_ok=True)
                #form.id_copy.data.save(id_copy_destination)
            if form.certificates.data:
                certificates_filename = secure_filename(form.certificates.data)
                certificates_destination = os.path.join(
                    current_app.config["UPLOAD_FOLDER_SUPPORTING_DOCUMENTS"],
                    certificates_filename,
                )
                os.makedirs(os.path.dirname(certificates_destination), exist_ok=True)
                #form.certificates.data.save(certificates_destination)
                user = insertUserIntodb(first_name, last_name, email, contact_number, occupation, gender, date_of_birth, address, postal_code, role, password)
            if role == "tutor":
                
                insert_copies(id_copy_destination ,certificates_filename,user['user_id'])
                send_volunteer_thank_you_email(user)
                send_documents_email(user, id_copy_filename, certificates_filename)
                flash(
                    "Thank you for registering with us, a message with more information has been sent to your email.",
                    "info",
                )
                return redirect(url_for("users.login"))
            else:
                user = insertUserIntodb(first_name,last_name,email,contact_number,occupation,gender,date_of_birth,address,postal_code,role,password)
                # Sends account confirmation mail to the user.
                send_confirmation(user['user_id'])

            flash('A confirmation link sent to your email. Please verify your account.', 'success')
            return redirect(url_for('accounts.login'))
    return render_template('create_account.html', form=form)


@accounts.route("/login", methods=["GET", "POST"])
def login() -> Response:
    
    """
    Handling user login functionality.
    If the user is already authenticated, they are redirected to the index page.

    This view handles both GET and POST requests:
    - GET: Renders the login form and template.
    - POST: Validates the form and authenticates the user.

    :return: Renders the login template on GET request or redirects based on the login status.
    """
    form = LoginForm()  # A form class for Login Account.
    
    if form.validate_on_submit():
        
        email = form.data.get("email", None)
        password = form.data.get("password", None)
        remember = form.data.get("remember", True)
        
        # Attempt to authenticate the user from the database.
        user = authenticate(email=email, password=password)
        
        if not user:
            flash("Invalid email or password. Please try again.", "error")
        else:
            if not user['active']:
                # User account is not active, send confirmation email.
                send_confirmation(user['user_id'])

                flash(
                    "Your account is not activate. We sent a confirmation link to your email",
                    "error",
                )
                return redirect(url_for("accounts.login"))

            session['email']=email
           
            user = get_user_by_email(email) #User.get_user_by_email(email=email)
            
            session['user']=user
            flash("You are logged in successfully.", "success")
            return redirect(url_for("accounts.index"))

        return redirect(url_for("accounts.login"))

    return render_template("login.html", form=form)


@accounts.route("/account/confirm", methods=["GET", "POST"])
def confirm_account() -> Response:
    """
    Handling account confirmation request via a token.
    If the token is valid and not expired, the user is activated.

    This view handles both GET and POST requests:
    - GET: Renders the account confirmation template.
    - POST: Activates the user account if the token is valid,
            logs the user in, and redirects to the index page.

    :return: Renders the confirmation template on GET request,
    redirects to login or index after POST.
    """
    token: str = request.args.get("token", None)

    # Verify the provided token and return token instance.
    auth_token = verify_token(
        token, current_app.config["ACCOUNT_CONFIRM_SALT"])

    if auth_token:
        # Retrieve the user instance associated with the token by providing user ID.
        user = get_user_by_id(auth_token['user_id'], raise_exception=True)
        
        if request.method == "POST":
            try:
                # Activate the user's account and expire the token.
                #user['active'] = True
                #auth_token['expire'] = True
                activate_user_and_expire_token(user['user_id'],token)
                # Commit changes to the database.
                #db.session.commit()
            except Exception as e:
                # Handle database error that occur during the account activation.
                raise InternalServerError


            flash(
                f"Welcome {user['first_name']+ ' ' + user['last_name']}, You're registered successfully.", "success"
            )
            return redirect(url_for("accounts.index"))

        return render_template("confirm_account.html", token=token)

    # If the token is invalid, return a 404 error
    return abort(HTTPStatus.NOT_FOUND)


@accounts.route('/send_user_data', methods=['POST'])
def send_user_data():
   
    # Get user data from the incoming request
    user_data= get_users()
    
    if not user_data:
        return {'error': 'No data provided'}
    # Example of the data structure expected by the other app
    target_url = 'http://127.0.0.1:7000/receive_user_data'

    try:
        # Send user data to another app (target app) via POST request
        response = requests.post(target_url, json=user_data)

        # Check if the request was successful
        if response.status_code == 200:
            return jsonify({'message': 'Data sent successfully', 'status': response.status_code}), 200
        else:
            return jsonify({'error': 'Failed to send data to the target app', 'status': response.status_code}), 500

    except requests.exceptions.RequestException as e:
        return jsonify({'error': str(e)}), 500





@accounts.route("/logout")
def logout() -> Response:
    session.clear()
    user=session.get('user')
    """
    Logs out the currently authenticated user
    and redirect them to the login page.

    :return: A redirect response to the login page with a success flash message.
    """
    # Log out the user and clear the session.
    logout_user()
    
    print("users ",user)
    flash("You're logout successfully.", "success")
    return render_template("index.html",user=user)


@accounts.route("/login-in")
def login_in() -> Response:

    """
    Logs out the currently authenticated user
    and redirect them to the login page.

    :return: A redirect response to the login page with a success flash message.
    """
    form=LoginForm() 
    
    flash("You're logout successfully.", "success")
    return render_template('login.html',form=form)

@accounts.route("/forgot/password", methods=["GET", "POST"])
def forgot_password() -> Response:
    """
    Handling forgot password requests by validating the provided email
    and sending a password reset link if the email is registered.

    This view handles both GET and POST requests:
    - GET: Renders the forgot password form and template.
    - POST: Validates the email and sends a reset link if the email exists in the system.

    :return: Renders the forgot password form on GET,
    redirects to login on success, or reloads the form on failure.
    """
    form = ForgotPasswordForm()

    if form.validate_on_submit():
        email = form.data.get("email")

        # Attempt to find the user by email from the database.
        user = get_user_by_email(email=email)

        if user:
            # Send a reset password link to the user's email.
            send_reset_password(user)

            flash("A reset password link sent to your email. Please check.", "success")
            return redirect(url_for("accounts.login"))

        flash("Email address is not registered with us.", "error")
        return redirect(url_for("accounts.forgot_password"))

    return render_template("forgot_password.html", form=form)


@accounts.route("/password/reset", methods=["GET", "POST"])
def reset_password() -> Response:
    """
    Handling password reset requests.

    This function allows users to reset their password by validating a token
    and ensuring the new password meets security criteria.

    This view handles both GET and POST requests:
    - GET: Renders the reset password form and template, if the token is valid.
    - POST: Validates the form, checks password strength, and updates the user's password.

    :return: Renders the reset password form on GET,
    redirects to login on success, or reloads the form on failure.
    """
    token = request.args.get("token", None)
    app.config["RESET_PASSWORD_SALT"] = os.getenv("RESET_PASSWORD_SALT", "reset_password_salt")
    # Verify the provided token and return token instance.
    auth_token = verify_token(
        
        token=token, salt=app.config["RESET_PASSWORD_SALT"])

    if auth_token:
        form = ResetPasswordForm()  # A form class to Reset User's Password.

        if form.validate_on_submit():
            password = form.data.get("password")
            confirm_password = form.data.get("confirm_password")

            # Regex pattern to validate password strength.
            re_pattern = r"(?=^.{8,}$)(?=.*\d)(?=.*[!@#$%^&*]+)(?![.\n])(?=.*[A-Z])(?=.*[a-z]).*$"

            if not (password == confirm_password):
                flash("Your new password field's not match.", "error")
            elif not re.match(re_pattern, password):
                flash(
                    "Please choose strong password. It contains at least one alphabet, number, and one special character.",
                    "warning",
                )
            else:
                try:
                    # Retrieve the user by the ID from the token and update their password.
                    user = get_user_by_id(auth_token['user_id'], raise_exception=True)
                    reset_password_and_expire_token(user['user_id'],password,auth_token['token'])
                    
                except Exception as e:
                    # Handle database error by raising an internal server error.
                    raise InternalServerError

                flash("Your password is changed successfully. Please login.", "success")
                return redirect(url_for("accounts.login"))

            return redirect(url_for("accounts.reset_password", token=token))

        return render_template("reset_password.html", form=form, token=token)

    # If the token is invalid, abort with a 404 Not Found status.
    return abort(HTTPStatus.NOT_FOUND)


@accounts.route("/change/password", methods=["GET", "POST"])
def change_password() -> Response:
    """
    Handling user password change requests.

    This function allows authenticated users to change their password by
    verifying the old password and ensuring the new password meets security criteria.

    This view handles both GET and POST requests:
    - GET: Renders the change password form and template.
    - POST: Validates the form, checks old password correctness, ensures the new
      password meets security standards, and updates the user's password.

    :return: Renders the change password form on GET,
    redirects to index on success, or reloads the form on failure.
    """
    form = ChangePasswordForm()  # A form class to Change User's Password.

    if form.validate_on_submit():
        old_password = form.data.get("old_password")
        new_password = form.data.get("new_password")
        confirm_password = form.data.get("confirm_password")

        # Retrieve the fresh user instance from the database.
        user = get_user_by_id(current_user['user_id'], raise_exception=True)

        # Regex pattern to validate password strength.
        re_pattern = (
            r"(?=^.{8,}$)(?=.*\d)(?=.*[!@#$%^&*]+)(?![.\n])(?=.*[A-Z])(?=.*[a-z]).*$"
        )

        if not check_password(old_password):
            flash("Your old password is incorrect.", "error")
        elif not (new_password == confirm_password):
            flash("Your new password field's not match.", "error")
        elif not re.match(re_pattern, new_password):
            flash(
                "Please choose strong password. It contains at least one alphabet, number, and one special character.",
                "warning",
            )
        else:
            try:
                # Update the user's password.
                #user.set_password(new_password)
                update_password(user['user_id'], new_password)
                # Commit changes to the database.
                #db.session.commit()
            except Exception as e:
                # Handle database error by raising an internal server error.
                raise InternalServerError

            flash("Your password changed successfully.", "success")
            return redirect(url_for("accounts.index"))

        return redirect(url_for("accounts.change_password"))

    return render_template("change_password.html", form=form)


@accounts.route("/")
@accounts.route("/home")
def index() -> Response:
    user=session.get('user')
   
    """
    Render the homepage for authenticated users.

    :return: Renders the `index.html` template.
    """
    return render_template("index.html",user=user)


@accounts.route("/profile", methods=["GET", "POST"])
def profile() -> Response:
    user_profile=session.get('user')
    
    if(not user_profile):
        return redirect(url_for("accounts.login"))
    form = EditUserProfileForm(obj=user_profile)

    # Retrieve the fresh user instance based on their ID
    user = get_users_with_profiles_by_id(user_profile['user_id'])
    print("user profile ",user)
  

    if form.validate_on_submit():
        # Retrieve form data
        id=user[0]['user_id']
        first_name = form.first_name.data
        last_name = form.last_name.data
        occupation = form.occupation.data
        contact_number = form.contact_number.data
        address = form.address.data
        postal_code = form.postal_code.data
        profile_image = form.profile_image.data
        bio = form.about.data

        # Update the user's main details
        # user.first_name = first_name
        # user.last_name = last_name
        # user.occupation = occupation
        # user.contact_number = contact_number
        # user.address = address
        # user.postal_code = postal_code
        # profile.bio = bio
        update_user_details(id, first_name, last_name, occupation, contact_number, address, postal_code)
        
        # Handle profile image upload if provided
        if profile_image and getattr(profile_image, "filename"):
            
            update_user_profile(id, bio, profile_image)
      

        flash("Your profile was updated successfully.", "success")
        return redirect(url_for("accounts.index"))
    
    return render_template("profile.html", form=form,user=user_profile)

base64_string=""



@accounts.route('/innovation')
def innovation():
    user=session.get('user')
    if user:
        id=user['user_id']
        if not id:
            return redirect(url_for('accounts.login'))
        # Redirect to another application running on a different server or port
        #user = get_user_by_id(id)
        # profile=get_profile_by_user_id(user['id'])
        # user['bio']=profile['bio']
    
        return redirect(f'http://127.0.0.1:9000?user={id}')
    else:
        return redirect(url_for("accounts.index"))

@accounts.route('/stem_app')
def stem_app():
        user=session.get('user')
        if user:
            id=user['user_id']
            if not id:
                return redirect(url_for('accounts.login'))
            profile=get_profile_by_user_id(id)
            if profile:
                user['bio']=profile['bio']
            return redirect(f'http://127.0.0.1:7000?user={id}')
        else:
            return redirect(url_for("accounts.index"))


@accounts.route('/inventory')
def inventory():
    user=session.get('user')
    if user:
        id=user['user_id']
        if not id:
            return redirect(url_for('accounts.login'))
        # Redirect to another application running on a different server or port
        user = get_users_with_profiles_by_id(id)
    
        return redirect(f'http://127.0.0.1:8000?user={id}')
    else:
        return redirect(url_for("accounts.index"))




@accounts.route('/stem-app-route/<string:id>', methods=['GET','POST'])
@cross_origin()  # Enable CORS for this route
def stemapproute(id):
    # Retrieve the logged-in user's email from the session
    
    if not id:
        return jsonify({'error': 'User not authenticated'}), 401  # Return a 401 status for unauthenticated requests

    # Retrieve user data by email
    user = get_user_by_id(id)
    if not user:
        return jsonify({'error': 'User not found'}), 404

 

    # Retrieve the user's profile data
    profile = get_profile_by_user_id(user['user_id'])
    if not profile:
        return jsonify({'error': 'Profile not found for user'}), 404

    # Add profile details to the user data
    profile['bio'] = profile.get('bio', '')
    profile['avatar'] = convert_image_to_base64_in_folder(profile.get('avator', ''))

    # Include other users in the response
    all_users = get_users()
  
    user_data = [u for u in all_users]
     
    user_data['bio']=profile['bio']
    user_data['avatar']=profile['avatar']
    # Debugging log to verify the data being returned
    print('User Data fetched data:', id)
   

    # Return the user data as JSON
    return jsonify(user_data), 200



@accounts.route('/stem_approute/<string:id>', methods=['GET','POST'])
@cross_origin()  # Enable CORS for this route
def stem_approute(id):
    # Retrieve the logged-in user's email from the session
    
    if not id:
        return jsonify({'error': 'User not authenticated'}), 401  # Return a 401 status for unauthenticated requests

    # Retrieve user data by email
    user = get_user_by_id(id)
    if not user:
        return jsonify({'error': 'User not found'}), 404

    
    
    
    return jsonify(user), 200
    
@accounts.route('/stemprofiles', methods=['GET'])
@cross_origin()  # Enable CORS for this route
def stemprofiles():
    
    if not id:
        return jsonify({'error': 'User not authenticated'}), 401  # Return a 401 status for unauthenticated requests

    # Retrieve user data
    user = get_users()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    profile=get_profile_by_user_id(id)
    if profile:
        user['bio']=profile['bio']
   
    # Return the user data as JSON
    return jsonify(user), 200

@accounts.route('/users_profiles', methods=['GET'])
@cross_origin()  # Enable CORS for this route
def users_profiles():
    
    if not id:
        return jsonify({'error': 'User not authenticated'}), 401  # Return a 401 status for unauthenticated requests

    # Retrieve user data
    user = get_users()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    profile=get_users_and_profiles()
    print("profiles ",profile)
    if profile:
        user['bio']=profile['bio']
    print(user)
    # Return the user data as JSON
    return jsonify(user), 200


@accounts.route('/stemuserprofiles/<string:id>', methods=['GET','POST'])
@cross_origin()  # Enable CORS for this route
def stemuserprofiles(id):
    
    user =get_user_by_id(id)
    if not user:
        return jsonify({'error': 'User not found'}), 404

    profile = get_profile_by_user_id(user['user_id'])
    if profile:
        user['bio'] = profile['bio']
        user['avatar'] = convert_image_to_base64_in_folder(profile['avator'])
    print("user ",user)
    # Return the user data as JSON
    return jsonify(user), 200


@accounts.route('/role/<string:id_copy>/<string:certificate>/<string:user_id>', methods=['GET','POST'])
@cross_origin()  # Enable CORS for this route
def role(id_copy,certificate,user_id):
    
    user =insert_copies(id_copy,certificate,user_id)
    
    # Return the user data as JSON
    return jsonify(user), 200

@accounts.route('/deleteuserprofiles/<string:id>', methods=['GET','POST'])
@cross_origin()  # Enable CORS for this route
def deleteuserprofiles(id):
    
    user =delete_user_and_profiles(id)
    if user:
        return jsonify({'error': 'User not deleted'}), 404
    
    # Return the user data as JSON
    return jsonify(user), 200

@accounts.route('/stemuserprofiles_status/<string:id>/<string:action>', methods=['GET','POST'])
@cross_origin()  # Enable CORS for this route
def stemuserprofiles_status(id,action):
    if action=="verify":
        user=verify_user(id)
    else:
        delete_user_and_profiles(id)
    
    # Return the user data as JSON
    return jsonify(user), 200




def compress_base64_string(base64_string: str) -> str:
    """
    Compress a Base64-encoded string.

    Args:
        b64_string (str): The Base64 string to compress.

    Returns:
        str: The compressed Base64 string.
    """
    try:

        
        binary_data = base64.b64decode(base64_string)
        # Compress the binary data
        compressed_data = gzip.compress(binary_data)
        # Encode the compressed data back into a Base64 string
        compressed_b64_string = base64.b64encode(compressed_data)
        compressed_b64_string = base64.b64encode(compressed_b64_string).decode('utf-8')
        return compressed_b64_string
    except Exception as e:
        raise ValueError(f"Error compressing Base64 string: {e}")



def create_folder(folder_name):
    # Create a new folder
    if not os.path.exists(folder_name):
        os.makedirs(folder_name)
        print(f"Folder '{folder_name}' created.")
    return folder_name

def save_filename_in_folder(filename, folder_name):
    # Save the filename in the created folder
    file_path = os.path.join(folder_name, filename)
    with open(file_path, "w") as file:
        file.write(filename)
    return file_path

def convert_image_to_base64_in_folder(image_filename):
    # Read and convert image to Base64 while it's in the folder
    
    try:
        config={'base_dir':'accounts\\static\\assets\\'}
        # Get base directory from config
        base_dir = config['base_dir']
    
        # Construct path for the uploads folder
        uploads_dir = os.path.join(base_dir, 'profile')
        # Ensure absolute path for consistency and security
        image_path = os.path.join(uploads_dir,image_filename)
        
        # Validate file existence and extension
        if not os.path.exists(image_path):
            print(f"Error: File '{image_filename}' does not exist.")
            return None

        # Check for supported image formats (add more as needed)
        if not image_path.lower().endswith(('.jpg', '.jpeg', '.png')):
            print(f"Error: Unsupported image format. Supported formats: JPG, JPEG, PNG.")
            return None

        with open(image_path, "rb") as image_file:
            encoded_string = base64.b64encode(image_file.read()).decode('utf-8')

        return encoded_string

    except FileNotFoundError:
        print(f"Error: File '{image_filename}' not found.")
    except Exception as e:
        print(f"An error occurred: {str(e)}")

    return None  # Return None on error


def delete_folder(folder_name):
    # Delete the folder and all its contents
    if os.path.exists(folder_name):
        shutil.rmtree(folder_name)
        print(f"Folder '{folder_name}' and its contents deleted.")
    
def process_image(filename):
    folder_name = "temp_folder"
    
    # 1. Create a folder
    create_folder(folder_name)
    
    # 2. Save the image filename in the folder
    image_path = save_filename_in_folder(filename, folder_name)
    
    # 3. Convert the image to Base64 while it's in the folder
    base64_string = convert_image_to_base64_in_folder(image_path)
    
    # 4. Delete the folder after conversion
    delete_folder(folder_name)
    
    # 5. Return the Base64-encoded string
    return base64_string


@app.route("/session")
def fetch_user_session_data():
    email=session["email"]
    return email



#get_non_superuser_users