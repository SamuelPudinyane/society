from http import HTTPStatus
from types import MappingProxyType


from werkzeug.exceptions import (
    BadRequest,
    Unauthorized,
    Forbidden,
    MethodNotAllowed,
    NotFound,
    InternalServerError,
    ServiceUnavailable,
)

from flask import Flask as FlaskAuth
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
import os
from dotenv import load_dotenv
load_dotenv()

# Default to Postgres; override via env `DATABASE_URI`.
# Example: postgresql+psycopg://user:password@host:5432/dbname
## Local DB URI (commented out)
# DATABASE_URI = (
#     os.environ.get(
#         "DATABASE_URI",
#         "postgresql+psycopg://postgres:postgres@localhost:5432/newx"
#     )
# )

# Use remote DB connection string
DATABASE_URI = os.environ.get("DATABASE_URI")

db = SQLAlchemy()
migrate = Migrate()


def create_app(config_type):
    """
    Create and configure the Flask application instance.
    """
    app = Flask(__name__, template_folder="templates")

    # Load database URI
    database_uri = os.environ.get('DATABASE_URI',DATABASE_URI)
    if not database_uri:
        raise RuntimeError("DATABASE_URI environment variable not set")
    app.config['SQLALCHEMY_DATABASE_URI'] = database_uri
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024 * 1024
    
    # Initialize extensions
    db.init_app(app)
    migrate.init_app(app, db)
    # Configure app
    config_application(app, config_type)

    # Initialize extensions
   

    # Configure extensions, blueprints, error handlers
    config_extention(app)
    config_blueprint(app)
    config_errorhandler(app)

    return app



def config_application(app, config_type):
    """
    Configure the Flask application based on the specified configuration type.
    """

    import config as conf

    if not config_type:
        raise RuntimeError("Configuration type must be provided.")

    # Immutable mapping of configuration types to their corresponding config objects.
    config_map = MappingProxyType(
        {
            "development": conf.development,
            "production": conf.production,
            "testing": conf.testing,
        }
    )

    # Get the configuration object based on the provided `config_type`.
    config = config_map.get(config_type)

    if not config:
        raise RuntimeError("Invalid configuration type: %s" % config_type)

    # Application configuration from object.
    app.config.from_object(config)


def config_blueprint(app):
    """
    Configure and register blueprints with the Flask application.
    """
    from .views import accounts

    app.register_blueprint(accounts)


def config_extention(app):
    """
    Configure application extensions.
    """
    from .extensions import login_manager
    from .extensions import bootstrap
    from .extensions import csrf
    from .extensions import mail

    login_manager.init_app(app)
    bootstrap.init_app(app)
    csrf.init_app(app)
    mail.init_app(app)

    config_login_manager(login_manager)

    # Exempt analytics tracker from CSRF to allow frontend POSTs
    try:
        from .views import track_event
        csrf.exempt(track_event)
    except Exception:
        pass


def config_login_manager(manager):
    """
    Configure with Flask-Login manager.
    """
    from .dbqueries import get_user_by_id

    manager.login_message = "You are not logged in to your account."
    manager.login_message_category = "warning"
    manager.login_view = "accounts.login"

    @manager.user_loader
    def user_loader(user_id):
        return get_user_by_id(user_id)


def config_errorhandler(app):
    """
    Configure error handlers for application.
    """
    from flask import flash, render_template, redirect, request, url_for

    @app.errorhandler(BadRequest)
    def bad_request(e):
        flash("Oops! There was a problem with your request. Please try again.", "error")
        return redirect(url_for("accounts.index"))

    @app.errorhandler(Unauthorized)
    def unauthorized(e):
        flash("You are not authorized to access this resource.", "error")
        return redirect(url_for("accounts.index"))

    @app.errorhandler(NotFound)
    def page_not_found(e):
        return render_template("error.html"), HTTPStatus.NOT_FOUND

    @app.errorhandler(MethodNotAllowed)
    def method_not_allowed(e):
        flash("Method not allowed.", "error")
        return redirect(url_for("accounts.index"))

    @app.errorhandler(InternalServerError)
    def internal_server_error(e):
        flash("Something went wrong with the internal server.", "error")
        return redirect(url_for("accounts.index"))

    @app.errorhandler(ServiceUnavailable)
    def service_unavailable(e):
        flash(e.description, "error")
        return redirect(request.path or url_for("accounts.login"))