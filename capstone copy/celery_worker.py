# celery_worker.py
from app import create_app
from task_defs import celery, make_celery

# Flask 앱 컨텍스트 로딩
flask_app = create_app()
make_celery(flask_app)
