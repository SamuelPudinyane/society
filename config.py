import os

from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent

MEDIA_ROOT = os.path.join(BASE_DIR, "accounts", "static", "assets")
UPLOAD_FOLDER_SUPPORTING_DOCUMENTS = os.path.join(MEDIA_ROOT, "supporting_documents")
UPLOAD_FOLDER = os.path.join(MEDIA_ROOT, "profile")

load_dotenv(os.path.join(BASE_DIR, ".env"))


class BaseConfig:
    # Application configuration
    DEBUG = False
    TESTING = False

    SITE_URL = os.getenv("SITE_DOMAIN", "http://localhost:5000")

    # Site secret key or bootstrap UI theme.
    SECRET_KEY = os.getenv("SECRET_KEY", "my-sekret-key")
    BOOTSTRAP_BOOTSWATCH_THEME = "sketchy"

    # WTF Form and recaptcha configuration
    WTF_CSRF_SECRET_KEY = os.getenv("CSRF_SECRET_KEY", None)
    WTF_CSRF_ENABLED = True

    UPLOAD_FOLDER_SUPPORTING_DOCUMENTS = os.path.join(MEDIA_ROOT, "supporting_documents")
    # SQLAlchemy (ORM) configuration
    SQLALCHEMY_ECHO = False
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Flask-Mail configuration
    MAIL_SERVER = os.getenv("MAIL_SERVER", "smtp.gmail.com")
    MAIL_USERNAME = os.getenv("MAIL_USERNAME")
    MAIL_PASSWORD = os.getenv("MAIL_PASSWORD")
    MAIL_PORT = 587
    MAIL_USE_TLS = True  # Enable TLS
    MAIL_USE_SSL = False  # SSL should remain False
    
    # Default Salt string for security tokens
    ACCOUNT_CONFIRM_SALT = os.getenv("ACCOUNT_CONFIRM_SALT", "account_confirm_salt")
    RESET_PASSWORD_SALT = os.getenv("RESET_PASSWORD_SALT", "reset_password_salt")
    CHANGE_EMAIL_SALT = os.getenv("CHANGE_EMAIL_SALT", "change_email_salt")



class Development(BaseConfig):
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URI", "sqlite:///db.sqlite3")


class Production(BaseConfig):
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URI", "sqlite:///db.sqlite3")


class Testing(BaseConfig):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///" + os.path.join(
        BASE_DIR, "db.sqlite3"
    )
    
    # Disable CSRF protection for testing.
    WTF_CSRF_ENABLED = False
    

development = Development()

production = Production()

testing = Testing()