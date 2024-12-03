from celery import shared_task

@shared_task
def limpiar_registros_antiguos():
    from django.utils.timezone import now
    from datetime import timedelta
    from .models import RegistroDispositivo

    limite = now() - timedelta(days=1)
    RegistroDispositivo.objects.filter(fecha__lt=limite).delete()
    return "Registros antiguos eliminados"
