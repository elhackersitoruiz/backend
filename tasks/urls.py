from django.urls import path
from .views import login  # Importa la vista de login

urlpatterns = [
    path('login/', login, name='login'),  # Ruta para el login
]
