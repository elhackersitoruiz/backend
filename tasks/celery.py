from celery import Celery

# Crea la instancia de Celery
app = Celery(
    'tasks',
    broker='redis://localhost:6379/0',  # Cambia localhost si Redis está en otro host
    backend='redis://localhost:6379/0',  # Opcional, para resultados
)

# Descubre tareas automáticamente en el módulo tasks
app.autodiscover_tasks(['tasks'])
