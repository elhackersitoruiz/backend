from __future__ import absolute_import, unicode_literals
import os
from celery import Celery

# Configurar el módulo de settings para Celery
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'tasks.settings')  # Cambia "tasks" si tu proyecto tiene otro nombre

# Crear instancia de Celery
app = Celery('tasks')

# Cargar configuración desde Django settings, usando el namespace CELERY_
app.config_from_object('django.conf:settings', namespace='CELERY')

# Descubrir automáticamente tareas definidas en aplicaciones registradas
app.autodiscover_tasks()

@app.task(bind=True)
def debug_task(self):
    print(f'Request: {self.request!r}')
