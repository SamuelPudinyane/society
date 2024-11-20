import os

from accounts import create_app
from waitress import serve
config_type = os.getenv("FLASK_ENV")

app = create_app(config_type)

if __name__ == "__main__":
    serve(app, host='0.0.0.0', port=8000)