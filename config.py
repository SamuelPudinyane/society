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

    # Analytics configuration
    # Time window to consider sessions "active" for admin metrics
    # Set to minutes; None disables window and uses latest-event logic only
    ANALYTICS_ACTIVE_WINDOW_MINUTES = int(os.getenv("ANALYTICS_ACTIVE_WINDOW_MINUTES", "30"))

    # Auto-logout after inactivity (minutes)
    INACTIVITY_LOGOUT_MINUTES = int(os.getenv("INACTIVITY_LOGOUT_MINUTES", "60"))



class Development(BaseConfig):
    DEBUG = True
    # SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URI", "sqlite:///db.sqlite3")  # Old connection string (commented out)
    SQLALCHEMY_DATABASE_URI = "postgresql://society_master_user:eCGrmS9dFFk9NDFVr814wKEjERVhEdcc@dpg-d4oa7si4d50c738nikr0-a.oregon-postgres.render.com/society_master"


class Production(BaseConfig):
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL")
    SQLALCHEMY_TRACK_MODIFICATIONS = False


class Testing(BaseConfig):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URI", "sqlite:///db.sqlite3")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Disable CSRF protection for testing.
    WTF_CSRF_ENABLED = False
    

development = Development()

production = Production()

testing = Testing()