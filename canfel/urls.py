"""
URL configuration for canfel project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
# urls.py
from django.contrib import admin
from django.urls import path, include
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)
from django.contrib.auth import views as auth_views


from tasks import views
from tasks.views import      AddPetView, CitasCreateView, CitasDeleteView, CitasListView, CitasListsinView, CitasUpdateView, CitasVerificarView, DeletePetView, GetUserView, PasswordChangeView, PasswordResetView, PetCirugiasView, PetDesparacitacionView, PetVacunasView, RegisterCirugiaView, RegisterDesparacitacionView, RegisterUserView, RegisterVacunaView, UpdateCirugiaView, UpdateDesparacitacionView, UpdateUserView, UpdateVacunaView, UsersWithPetsView, delete_user

urlpatterns = [
    path('admin/', admin.site.urls),

    path('api_authorization/', include('rest_framework.urls')),
    
    # JWT Authentication URLs
 path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    
    path('update_user/<int:user_id>/', UpdateUserView.as_view(), name='update_user'),

    
    # Auth Endpoints
    path('register/', RegisterUserView.as_view(), name='register-user'),
    
    path('add-pet/', AddPetView.as_view(), name='add-pet'),
    path('pets/<int:pet_id>/delete/', DeletePetView.as_view(), name='delete_pet'),


    #registro de carnet
    path('register/vacuna/<int:pet_id>/', RegisterVacunaView.as_view(), name='register-vacuna'),
    path('register/desparacitacion/<int:pet_id>/', RegisterDesparacitacionView.as_view(), name='register-desparacitacion'),
    path('register/cirugia/<int:pet_id>/', RegisterCirugiaView.as_view(), name='register-cirugia'),

    #visualizacion del carnet

    path('pet/<int:pet_id>/vacunas/', PetVacunasView.as_view(), name='pet-vacunas'),
    path('pet/<int:pet_id>/desparacitacion/', PetDesparacitacionView.as_view(), name='pet-desparacitacion'),
    path('pet/<int:pet_id>/cirugias/', PetCirugiasView.as_view(), name='pet-cirugias'),


     # Actualización del carnet
    path('update/vacuna/<int:pet_id>/<int:vacuna_id>/', UpdateVacunaView.as_view(), name='update-vacuna'),
    path('update/desparacitacion/<int:pet_id>/<int:desparacitacion_id>/', UpdateDesparacitacionView.as_view(), name='update-desparacitacion'),
    path('update/cirugia/<int:pet_id>/<int:cirugia_id>/', UpdateCirugiaView.as_view(), name='update-cirugia'),

    #eliminar del carnet
    path('delete/vacuna/<int:pet_id>/<int:vacuna_id>/', views.delete_vacuna, name='delete_vacuna'),
    path('delete/cirugia/<int:pet_id>/<int:cirugia_id>/', views.delete_cirugia, name='delete_cirugia'),
    path('delete/desparacitacion/<int:pet_id>/<int:desparacitacion_id>/', views.delete_desparacitacion, name='delete_vacuna'),


    path('api/delete_user/<str:dni>/', delete_user, name='delete_user'),


    path('users-with-pets/', UsersWithPetsView.as_view(), name='users-with-pets'),



    path('citas/lista/sin/', CitasListsinView.as_view(), name='citas-list'),  # Ver todas las citas

    path('citas/lista/', CitasListView.as_view(), name='citas-list'),  # Ver todas las citas

    path('citas/', CitasCreateView.as_view(), name='citas-create'),

    path('api/citas/verificar/<uuid:token>/', CitasVerificarView.as_view(), name='citas-verificar'),  # Verificar cita

    path('citas/update/<int:id>/', CitasUpdateView.as_view(), name='citas-update'),
    
    # Eliminar una cita por ID
    path('citas/delete/<int:id>/', CitasDeleteView.as_view(), name='citas-delete'),

    path('verificar_cita/', views.verificar_fecha, name='verificar_cita'),



    path('api/get_user/<int:user_id>/', GetUserView.as_view(), name='get_user'),


    
    #   Register Endpoint

    # PasswordReset
    path('password_reset/', PasswordResetView.as_view(), name='password_reset'),
    path('password_reset/done/', auth_views.PasswordResetDoneView.as_view(), name='password_reset_done'),
    path('reset/<uidb64>/<token>/', auth_views.PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    path('reset/done/', auth_views.PasswordResetCompleteView.as_view(), name='password_reset_complete'),
    path('password-change/', PasswordChangeView.as_view(), name='password-change'),

    path('api/', include('tasks.urls')),  # Incluir las rutas de tu aplicación




    



]

