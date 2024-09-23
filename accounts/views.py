from flask import abort, render_template, request, redirect, url_for, flash,session
from http import HTTPStatus
from werkzeug.exceptions import InternalServerError
from flask import Blueprint, Response
from flask_login import (
        current_user,
        login_required,
        login_user,
        logout_user
    )

from accounts.decorators import authentication_redirect
from accounts.email_utils import (
    send_reset_password,
)

from accounts.extensions import database as db
from accounts.models import User, Profile
from accounts.forms import (
        RegisterForm, 
        LoginForm, 
        ForgotPasswordForm,
        ResetPasswordForm,
        ChangePasswordForm,
        EditUserProfileForm
    )
from flask import Flask
from datetime import datetime, timedelta
import re
import os


"""
This accounts blueprint defines routes and templates related to user management
within our application.
"""
accounts = Blueprint('accounts', __name__, template_folder='templates')
app = Flask(__name__) 

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

            user = User.create(
                first_name=first_name,
                last_name=last_name,
                email=email,
                date_of_birth=date_of_birth,
                gender=gender,
                occupation=occupation,
                contact_number=contact_number,
                address=address,
                postal_code=postal_code,
                role=role,
                password=password
            )
                
            # Sends account confirmation mail to the user.
            user.send_confirmation()
            flash('A confirmation link sent to your email. Please verify your account.', 'success')
            return redirect(url_for('accounts.login'))
    return render_template('create_account.html', form=form)


@accounts.route("/login", methods=["GET", "POST"])
@authentication_redirect
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
        # Attempt to authenticate the user from the database.
        user = User.authenticate(email=email, password=password)

        if not user:
            flash("Invalid email or password. Please try again.", "error")
        else:
            if not user.is_active:
                # User account is not active, send confirmation email.
                user.send_confirmation()

                flash(
                    "Your account is not activate. We sent a confirmation link to your email",
                    "error",
                )
                return redirect(url_for("accounts.login"))

            # Log the user in and set the session to remember the user for (15 days)
            login_user(user, remember=True, duration=timedelta(days=15))
            session["email"]=email
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
    auth_token = User.verify_token(token=token)

    if auth_token:
        # Retrieve the user instance associated with the token by providing user ID.
        user = User.get_user_by_id(auth_token.user_id, raise_exception=True)

        if request.method == "POST":
            try:
                # Activate the user's account and expire the token.
                user.active = True
                auth_token.expire = True

                # Commit changes to the database.
                db.session.commit()
            except Exception as e:
                # Handle database error that occur during the account activation.
                raise InternalServerError

            # Log the user in and set the session to remember the user for (15 days).
            login_user(user, remember=True, duration=timedelta(days=15))

            flash(
                f"Welcome {user.first_name+ ' ' + user.last_name}, You're registered successfully.", "success"
            )
            return redirect(url_for("accounts.index"))

        return render_template("confirm_account.html", token=token)

    # If the token is invalid, return a 404 error
    return abort(HTTPStatus.NOT_FOUND)


@accounts.route("/logout")
@login_required
def logout() -> Response:
    """
    Logs out the currently authenticated user
    and redirect them to the login page.

    :return: A redirect response to the login page with a success flash message.
    """
    # Log out the user and clear the session.
    logout_user()

    flash("You're logout successfully.", "success")
    return redirect(url_for("accounts.login"))


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
        user = User.get_user_by_email(email=email)

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

    # Verify the provided token and return token instance.
    auth_token = User.verify_token(token=token)

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
                    user = User.get_user_by_id(auth_token.user_id, raise_exception=True)
                    user.set_password(password)

                    # Mark the token as expired after the password is reset.
                    auth_token.expire = True

                    # Commit changes to the database.
                    db.session.commit()
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
@login_required
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
        user = User.get_user_by_id(current_user.id, raise_exception=True)

        # Regex pattern to validate password strength.
        re_pattern = (
            r"(?=^.{8,}$)(?=.*\d)(?=.*[!@#$%^&*]+)(?![.\n])(?=.*[A-Z])(?=.*[a-z]).*$"
        )

        if not user.check_password(old_password):
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
                user.set_password(new_password)

                # Commit changes to the database.
                db.session.commit()
            except Exception as e:
                # Handle database error by raising an internal server error.
                raise InternalServerError

            flash("Your password changed successfully.", "success")
            return redirect(url_for("accounts.index"))

        return redirect(url_for("accounts.change_password"))

    return render_template("change_password.html", form=form)


@accounts.route("/")
@accounts.route("/home")
@login_required
def index() -> Response:
    """
    Render the homepage for authenticated users.

    :return: Renders the `index.html` template.
    """
    return render_template("index.html")


@accounts.route("/profile", methods=["GET", "POST"])
@login_required
def profile() -> Response:
    """
    Handling the user's profile page,
    allowing them to view and edit their profile information.

    Methods:
        GET: Render the profile template with the user's current information.
        POST: Update the user's profile with the submitted form data.

    Returns:
        Response: The rendered profile template or a redirect after form submission.
    """
    form = EditUserProfileForm()  # A form class to Edit User's Profile.

    # Retrieve the fresh user instance based on their ID.
    user = User.get_user_by_id(current_user.id, raise_exception=True)

    if form.validate_on_submit():
        first_name = form.data.get("first_name")
        last_name = form.data.get("last_name")
        occupation = form.data.get("occupation")
        contact_number = form.data.get("contact_number")
        address = form.data.get("address")
        postal_code = form.data.get("postal_code")
        profile_image = form.data.get("profile_image")
        about = form.data.get("about")

        # Check if the new email already exists and belongs to a different user.
        email_exist = User.query.filter(
            User.email == User.email, User.id != current_user.id
        ).first()

        if email_exist:
            flash("Email already exists. Choose another.", "error")
        else:
            try:
                # Update the user's profile details.
                user.first_name = first_name
                user.last_name = last_name
                user.occupation = occupation
                user.contact_number = contact_number
                user.address = address
                user.postal_code = postal_code
                user.profile.bio = about

                # Handle profile image upload if provided.
                if profile_image and getattr(profile_image, "filename"):
                    user.profile.set_avator(profile_image)

                # Commit changes to the database.
                db.session.commit()
            except Exception as e:
                # Handle database error by raising an internal server error.
                raise InternalServerError

            flash("Your profile update successfully.", "success")
            return redirect(url_for("accounts.index"))

        return redirect(url_for("accounts.profile"))

    return render_template("profile.html", form=form)



@app.route("/session")
def fetch_user_session_data():
    email=session["email"]
    return email
