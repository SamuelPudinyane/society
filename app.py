import os
from dotenv import load_dotenv
from accounts import create_app
from waitress import serve

# Load environment variables from .env
load_dotenv()

# Determine environment
config_type = os.getenv("FLASK_ENV", "development")

# Create app
app = create_app(config_type)

# Set additional configs before initializing extensions
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URI')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024 * 1024  # 5 GB

if __name__ == "__main__":
    serve(app, host='0.0.0.0', port=5000)
