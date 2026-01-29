"""
Celery configuration for Email Verifier Project
"""
from __future__ import absolute_import, unicode_literals
import os
from celery import Celery
from django.conf import settings

# Set the default Django settings module for the 'celery' program.
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings')

# Create Celery app
app = Celery('email_verifier')

# Using a string here means the worker doesn't have to serialize
# the configuration object to child processes.
# - namespace='CELERY' means all celery-related configuration keys
#   should have a `CELERY_` prefix.
app.config_from_object('django.conf:settings', namespace='CELERY')

# Load task modules from all registered Django apps.
app.autodiscover_tasks(lambda: settings.INSTALLED_APPS)

# Celery Beat Schedule (for periodic tasks if needed)
app.conf.beat_schedule = {
    # Example: Clean up old jobs every day
    # 'cleanup-old-jobs': {
    #     'task': 'verifier.tasks.cleanup_old_jobs',
    #     'schedule': crontab(hour=0, minute=0),
    # },
}

# Task configuration
app.conf.update(
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='Asia/Kolkata',
    enable_utc=True,
    task_track_started=True,
    task_time_limit=30 * 60,  # 30 minutes max per task
    task_soft_time_limit=25 * 60,  # Soft limit at 25 minutes
    worker_prefetch_multiplier=1,  # Prevent workers from grabbing too many tasks
    worker_max_tasks_per_child=1000,  # Restart worker after 1000 tasks (prevent memory leaks)
)


@app.task(bind=True, ignore_result=True)
def debug_task(self):
    """Debug task to test Celery is working"""
    print(f'Request: {self.request!r}')
