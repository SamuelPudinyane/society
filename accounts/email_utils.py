import os
import typing as t
import json
from smtplib import SMTPException
from werkzeug.exceptions import ServiceUnavailable

from flask import render_template, url_for,current_app
from flask_mail import Message

from accounts.extensions import mail
from accounts.dbqueries import (generate_token,get_user_tokens_by_user_id,get_user_by_id)
from accounts.utils import get_full_url
from flask import current_app as app

def send_mail(subject: t.AnyStr, recipients: t.List[str], body: t.Text):
    """
    Sends an email using the Flask-Mail extension.

    :param subject: The subject of the email.
    :param recipients: A list of recipient email addresses.
    :param body: The body content of the email.

    :raises ValueError: If the MAIL_USERNAME environment variable is not set.
    :raises ServiceUnavailable: If the SMTP service is unavailable.
    """
    sender: str = os.environ.get("MAIL_USERNAME", None)

    if not sender:
        raise ValueError("MAIL_USERNAME environment variable is not set")

    # Create the message
    message = Message(subject=subject, sender=sender, recipients=recipients)
    message.body = body

    print(message.body)  # Debugging line, optional

    try:
        # Flask-Mail handles connection automatically
        mail.connect()
        mail.send(message)
        print("Email sent successfully!")  # Optional, for confirmation
    except SMTPException as e:
        # Log the detailed exception for debugging purposes
        app.logger.error(f"SMTPException: {e}")
        raise ServiceUnavailable(
            description=(
                "The SMTP mail service is currently not available. "
                "Please try later or contact the developers team."
            )
        )
    except Exception as e:
        # Catch any other exceptions and log them
        app.logger.error(f"General Exception in send_mail: {e}")
        raise ServiceUnavailable(
            description=(
                "An unexpected error occurred while sending the email. "
                "Please try again later or contact support."
            )
        )

def send_confirmation_mail(user):
    print("this user is here  ",user)
    subject: str = "Verify Your Account"
    #user=get_user_tokens_by_user_id(user)
    
    salt=app.config["ACCOUNT_CONFIRM_SALT"]
    token: str = generate_token(salt,user)
    user=get_user_by_id(user)
    verification_link: str = get_full_url(
        url_for("accounts.confirm_account", token=token)
    )
    
    
    context = render_template(
        "emails/verify_account.txt",
        fullname=str(user.get('firstname',''))+ " " + str(user.get('lastname','')),
        verification_link=verification_link,
    )

    send_mail(subject=subject, recipients=[user['email']], body=context)


def send_reset_password(user):
    subject: str = "Reset Your Password"

    token: str = generate_token(user=user, salt=app.config["RESET_PASSWORD_SALT"])

    reset_link: str = get_full_url(url_for("accounts.reset_password", token=token))

    context = render_template(
        "emails/reset_password.txt", email=user['email'], reset_link=reset_link
    )

    send_mail(subject=subject, recipients=[user['email']], body=context)


def send_volunteer_thank_you_email(user):
    try:
        username=user['first_name']+ " "+['last_name']
        email=user['email']
        sender = os.environ.get("MAIL_USERNAME", "no-reply@example.com")
        msg = Message("Thank You for Registering as a Tutor", sender=sender, recipients=[email])
        username = user.username if user else "User"
        msg.body = render_template("emails/volunteer_thank_you_email.txt", username=username)
        mail.send(msg)
        print("Thank-you email sent successfully!")
    except SMTPException as e:
        print(f"SMTP error: {str(e)}")
        raise ServiceUnavailable("SMTP mail service is currently unavailable. Please try later.")
    except Exception as e:
        print(f"General error: {str(e)}")
        raise ServiceUnavailable("An error occurred while sending the email. Please try later.")
    
def send_application_accepted_email(user):
    try:
        username=user['first_name']+ " "+['last_name']
        email=user['email']
        sender = os.environ.get("MAIL_USERNAME", "no-reply@example.com")
        username = user.username if user else "User"
        msg = Message("Application Accepted", sender=sender, recipients=[email])
        msg.body = render_template("emails/application_accepted_email.txt", username=username)
        mail.send(msg)
        print("Application accepted email sent successfully!")
    except SMTPException as e:
        print(f"SMTP error: {str(e)}")
        raise ServiceUnavailable("SMTP mail service is unavailable. Please try again later.")
    except Exception as e:
        print(f"General error: {str(e)}")
        raise ServiceUnavailable("An error occurred while sending the email. Please try again later.")


def send_documents_email(user, id_copy_filename, certificates_filename):
    try:
      
        if not user:
            print("User not found!")
            return

        recipient = os.environ.get("MAIL_USERNAME", "admin@example.com")
        msg = Message("Documents Attached", sender=user['email'], recipients=[recipient])
        msg.body = f"User {user['username']} has registered as a tutor."

        # Attach ID Copy
        if id_copy_filename:
            id_copy_path = os.path.join(
                current_app.config["UPLOAD_FOLDER_SUPPORTING_DOCUMENTS"], id_copy_filename
            )
            if os.path.exists(id_copy_path):
                with open(id_copy_path, "rb") as id_copy_file:
                    msg.attach(id_copy_filename, "application/pdf", id_copy_file.read())
                print(f"ID copy attached: {id_copy_path}")
            else:
                print(f"ID copy file not found: {id_copy_path}")

        # Attach Certificates
        if certificates_filename:
            certificates_path = os.path.join(
                current_app.config["UPLOAD_FOLDER_SUPPORTING_DOCUMENTS"], certificates_filename
            )
            if os.path.exists(certificates_path):
                with open(certificates_path, "rb") as certificates_file:
                    msg.attach(certificates_filename, "application/pdf", certificates_file.read())
                print(f"Certificate attached: {certificates_path}")
            else:
                print(f"Certificate file not found: {certificates_path}")

        mail.send(msg)
        print("Documents email sent successfully!")
    except Exception as e:
        print(f"Error in send_documents_email: {str(e)}")


