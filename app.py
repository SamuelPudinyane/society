import os

from accounts import create_app
from waitress import serve
config_type = os.getenv("FLASK_ENV","development")

app = create_app(config_type)
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024 * 1024
if __name__ == "__main__":
    serve(app, host='0.0.0.0', port=5000)