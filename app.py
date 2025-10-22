import os
from dotenv import load_dotenv


# Load environment variables from .env
load_dotenv()

from accounts import create_app
from waitress import serve
# Determine environment
config_type = os.getenv("FLASK_ENV", "development")

# Create app
app = create_app(config_type)


if __name__ == "__main__":
    serve(app, host='0.0.0.0', port=5000)
