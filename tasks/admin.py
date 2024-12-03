from django.contrib import admin
from .models import CustomUser, Pet, Vacunas, Cirugias, Desparacitacion

# Registra el modelo de usuario personalizado
admin.site.register(CustomUser)
admin.site.register(Pet)
admin.site.register(Vacunas)
admin.site.register(Cirugias)
admin.site.register(Desparacitacion)
