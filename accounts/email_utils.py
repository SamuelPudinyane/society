import os
import typing as t

from smtplib import SMTPException
from werkzeug.exceptions import ServiceUnavailable

from flask import render_template, url_for
from flask_mail import Message

from accounts.extensions import mail
from accounts.models import User
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

def send_confirmation_mail(user: User = None):
    subject: str = "Verify Your Account"

    token: str = user.generate_token()

    verification_link: str = get_full_url(
        url_for("accounts.confirm_account", token=token)
    )

    context = render_template(
        "emails/verify_account.txt",
        fullname=user.first_name+ " " + user.last_name,
        verification_link=verification_link,
    )

    send_mail(subject=subject, recipients=[user.email], body=context)


def send_reset_password(user: User = None):
    subject: str = "Reset Your Password"

    token: str = user.generate_token()

    reset_link: str = get_full_url(url_for("accounts.reset_password", token=token))

    context = render_template(
        "emails/reset_password.txt", email=user.email, reset_link=reset_link
    )

    send_mail(subject=subject, recipients=[user.email], body=context)
