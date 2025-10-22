import os
from dotenv import load_dotenv
from accounts import create_app, db
from flask_migrate import Migrate
from flask_script import Manager

# Load environment variables from .env
load_dotenv()

from accounts import create_app
from waitress import serve
# Determine environment
config_type = os.getenv("FLASK_ENV", "development")

# Create app
app = create_app(config_type)

# Setup Migrate
migrate = Migrate(app, db)

# Setup Manager
manager = Manager(app)

# Add the 'db' command to manager
from flask_migrate import MigrateCommand
manager.add_command('db', MigrateCommand)

if __name__ == "__main__":
    serve(app, host='0.0.0.0', port=5000)
