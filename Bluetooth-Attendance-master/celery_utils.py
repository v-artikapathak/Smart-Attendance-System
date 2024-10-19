from celery import Celery
from flask import Flask

def make_celery(app):
    # Initialize Celery with Flask's configuration
    celery = Celery(app.import_name, backend=app.config['CELERY_RESULT_BACKEND'], broker=app.config['CELERY_BROKER_URL'])
    celery.conf.update(app.config)

    class ContextTask(celery.Task):
        def __call__(self, *args, **kwargs):  # Fixed __call__
            with app.app_context():
                return self.run(*args, **kwargs)

    celery.Task = ContextTask
    return celery

# Initialize Flask app
app = Flask(__name__)  # Ensure parentheses are correct

# Flask configuration for Celery
app.config.update(
    CELERY_BROKER_URL='redis://localhost:6379/0',
    CELERY_RESULT_BACKEND='redis://localhost:6379/0'
)

# Initialize Celery with the Flask app
celery = make_celery(app)
