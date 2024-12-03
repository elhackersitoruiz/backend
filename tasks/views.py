from datetime import timedelta
from django.http import JsonResponse
from django.shortcuts import render
from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.decorators import api_view
from rest_framework.permissions import IsAuthenticated
#from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.models import User
from django.contrib.auth import authenticate
from django.db.models import Q

from django.contrib.auth.models import User
from django.utils import timezone
from django_ratelimit.decorators import ratelimit


from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated


from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from django.shortcuts import get_object_or_404
from .models import CustomUser

@api_view(['DELETE'])
def delete_user(request, dni):
    """
    Elimina un usuario basado en su DNI.
    """
    user = get_object_or_404(CustomUser, dni=dni)  # Busca el usuario por DNI o lanza un error 404

    try:
        user.delete()  # Elimina el usuario
        return Response({"message": "Usuario eliminado exitosamente."}, status=status.HTTP_200_OK)
    except Exception as e:
        return Response(
            {"error": f"No se pudo eliminar el usuario: {str(e)}"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )






#import logging
#from rest_framework.views import APIView
#from rest_framework.response import Response
#from rest_framework import status
#from rest_framework.permissions import IsAdminUser
#from django.core.mail import send_mail
#from .models import Pet, User
#from .serializers import PetSerializer

# Configurar logger
#logger = logging.getLogger('pet_management')

#class AddPetView(APIView):

 #   def post(self, request):
  #      user_id = request.data.get('user_id')  # ID del usuario al que se asignará la mascota
   #     user = User.objects.filter(id=user_id).first()

    #    if not user:
     #       logger.error(f"Usuario con ID {user_id} no encontrado.")
      #      return Response({"error": "Usuario no encontrado."}, status=status.HTTP_404_NOT_FOUND)
#
 #       pet_data = request.data
  #      pet_data['user'] = user.id
#
 #       serializer = PetSerializer(data=pet_data)
  #      if serializer.is_valid():
   #         pet = serializer.save()
#
            # Registrar log de creación
 #           logger.info(f"Mascota '{pet.namepet}' creada por {request.user.username} para {user.username}.")

            # Enviar correo al usuario
  #          send_mail(
   #             'Nueva mascota registrada',
    #            f"Hola {user.username}, se ha registrado a {pet.namepet} como tu mascota.",
     #           'tu_correo@gmail.com',
      #          [user.email],
       #         fail_silently=False,
        #    )

         #   return Response({
          #      "message": f"¡Mascota '{pet.namepet}' asignada con éxito a {user.username}!",
           #     "pet": serializer.data
            #}, status=status.HTTP_201_CREATED)

        #logger.warning(f"Error al registrar mascota: {serializer.errors}")
        #return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .serializers import CustomUserSerializer

class RegisterUserView(APIView):
    def post(self, request, *args, **kwargs):
        serializer = CustomUserSerializer(data=request.data)

        if serializer.is_valid():
            user = serializer.save()  # Esto llama al método create que definimos antes
            return Response({
                'message': 'Usuario creado con éxito',
                'user': CustomUserSerializer(user).data
            }, status=status.HTTP_201_CREATED)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from .serializers import CustomUserSerializer
from .models import CustomUser  # Asegúrate de importar tu modelo de usuario

class UpdateUserView(APIView):
    def put(self, request, *args, **kwargs):
        # Obtén el usuario de la base de datos, asumiendo que el ID se pasa como parte de la URL
        try:
            user = CustomUser.objects.get(id=kwargs['user_id'])  # Asume que 'user_id' está en la URL
        except CustomUser.DoesNotExist:
            return Response({'message': 'Usuario no encontrado'}, status=status.HTTP_404_NOT_FOUND)

        # Usa el serializador para validar y actualizar los datos
        serializer = CustomUserSerializer(user, data=request.data, partial=True)  # 'partial=True' permite actualizaciones parciales

        if serializer.is_valid():
            updated_user = serializer.save()  # Actualiza el usuario
            return Response({
                'message': 'Usuario actualizado con éxito',
                'user': CustomUserSerializer(updated_user).data
            }, status=status.HTTP_200_OK)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.shortcuts import get_object_or_404
from .serializers import CustomUserSerializer
from .models import CustomUser  # Reemplázalo con el modelo de usuario que estés utilizando

class GetUserView(APIView):
    def get(self, request, user_id, *args, **kwargs):
        # Obtiene el usuario o lanza un error 404 si no existe
        user = get_object_or_404(CustomUser, id=user_id)
        
        # Serializa los datos del usuario
        serializer = CustomUserSerializer(user)
        
        return Response(serializer.data, status=status.HTTP_200_OK)




from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from .serializers import PetSerializer

class AddPetView(APIView):
    def post(self, request, *args, **kwargs):
        # Aquí usamos el serializador para validar los datos de la mascota
        serializer = PetSerializer(data=request.data, context={'request': request})
        
        if serializer.is_valid():
            # Si los datos son válidos, creamos la mascota
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from django.shortcuts import get_object_or_404
from .models import Pet

class DeletePetView(APIView):
    """
    Vista para eliminar una mascota específica.
    """
    def delete(self, request, pet_id, *args, **kwargs):
        # Buscar la mascota en la base de datos
        pet = get_object_or_404(Pet, id=pet_id)
        
        # (Opcional) Verificar si el usuario tiene permisos para eliminar
        # if pet.owner != request.user:
        #     return Response({"error": "No tienes permisos para eliminar esta mascota."}, status=status.HTTP_403_FORBIDDEN)
        
        # Eliminar la mascota
        pet.delete()
        return Response({"message": "Mascota eliminada con éxito."}, status=status.HTTP_200_OK)



from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from .models import Pet, Vacunas
from .serializers import VacunasSerializer

class RegisterVacunaView(APIView):
    def post(self, request, pet_id):
        try:
            pet = Pet.objects.get(id=pet_id)
        except Pet.DoesNotExist:
            return Response({"detail": "Mascota no encontrada"}, status=status.HTTP_404_NOT_FOUND)

        # Agregar la vacuna a la mascota
        data = request.data
        data['pet'] = pet.id  # Asignar la mascota al campo 'pet'
        serializer = VacunasSerializer(data=data)

        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)




from .serializers import DesparacitacionSerializer

class RegisterDesparacitacionView(APIView):
    def post(self, request, pet_id):
        try:
            pet = Pet.objects.get(id=pet_id)
        except Pet.DoesNotExist:
            return Response({"detail": "Mascota no encontrada"}, status=status.HTTP_404_NOT_FOUND)

        # Agregar la desparacitación a la mascota
        data = request.data
        data['pet'] = pet.id  # Asignar la mascota al campo 'pet'
        serializer = DesparacitacionSerializer(data=data)

        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



from .serializers import CirugiasSerializer

class RegisterCirugiaView(APIView):
    def post(self, request, pet_id):
        try:
            pet = Pet.objects.get(id=pet_id)
        except Pet.DoesNotExist:
            return Response({"detail": "Mascota no encontrada"}, status=status.HTTP_404_NOT_FOUND)

        # Agregar la cirugía a la mascota
        data = request.data
        data['pet'] = pet.id  # Asignar la mascota al campo 'pet'
        serializer = CirugiasSerializer(data=data)

        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import Pet, Vacunas
from .serializers import VacunasSerializer

class PetVacunasView(APIView):
    def get(self, request, pet_id):
        try:
            pet = Pet.objects.get(id=pet_id)
        except Pet.DoesNotExist:
            return Response({"detail": "Mascota no encontrada"}, status=status.HTTP_404_NOT_FOUND)

        vacunas = Vacunas.objects.filter(pet=pet)
        serializer = VacunasSerializer(vacunas, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)



from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import Pet, Desparacitacion
from .serializers import DesparacitacionSerializer

class PetDesparacitacionView(APIView):
    def get(self, request, pet_id):
        try:
            pet = Pet.objects.get(id=pet_id)
        except Pet.DoesNotExist:
            return Response({"detail": "Mascota no encontrada"}, status=status.HTTP_404_NOT_FOUND)

        desparacitaciones = Desparacitacion.objects.filter(pet=pet)
        serializer = DesparacitacionSerializer(desparacitaciones, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import Pet, Cirugias
from .serializers import CirugiasSerializer

class PetCirugiasView(APIView):
    def get(self, request, pet_id):
        try:
            pet = Pet.objects.get(id=pet_id)
        except Pet.DoesNotExist:
            return Response({"detail": "Mascota no encontrada"}, status=status.HTTP_404_NOT_FOUND)

        cirugias = Cirugias.objects.filter(pet=pet)
        serializer = CirugiasSerializer(cirugias, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import Vacunas
from .serializers import VacunasSerializer

class UpdateVacunaView(APIView):
    def put(self, request, pet_id, vacuna_id):
        try:
            vacuna = Vacunas.objects.get(id=vacuna_id, pet_id=pet_id)
        except Vacunas.DoesNotExist:
            return Response({"error": "Vacuna no encontrada."}, status=status.HTTP_404_NOT_FOUND)
        
        # Usa el serializer para validar y actualizar los datos
        serializer = VacunasSerializer(vacuna, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import Pet, Desparacitacion
from .serializers import DesparacitacionSerializer

class UpdateDesparacitacionView(APIView):
    def put(self, request, pet_id, desparacitacion_id):
        try:
            desparacitacion = Desparacitacion.objects.get(id=desparacitacion_id, pet_id=pet_id)

        except Desparacitacion.DoesNotExist:
            return Response({"error": "Desparacitacion no encontrada."}, status=status.HTTP_404_NOT_FOUND)
        
        # Usa el serializer para validar y actualizar los datos
        serializer = DesparacitacionSerializer(desparacitacion, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    


from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import Pet, Cirugias
from .serializers import CirugiasSerializer

class UpdateCirugiaView(APIView):
    def put(self, request, pet_id, cirugia_id):
        try:
            cirugia = Cirugias.objects.get(id=cirugia_id, pet_id=pet_id)

        except Cirugias.DoesNotExist:
            return Response({"error": "Cirugias no encontrada."}, status=status.HTTP_404_NOT_FOUND)
        
        # Usa el serializer para validar y actualizar los datos
        serializer = CirugiasSerializer(cirugia, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status

@api_view(['DELETE'])
def delete_vacuna(request, pet_id, vacuna_id):
    try:
        vacuna = Vacunas.objects.get(id=vacuna_id, pet_id=pet_id)
        vacuna.delete()
        return Response({"message": "Vacuna eliminada exitosamente."}, status=status.HTTP_200_OK)
    except Vacunas.DoesNotExist:
        return Response({"error": "Vacuna no encontrada."}, status=status.HTTP_404_NOT_FOUND)




from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import Pet, Desparacitacion

@api_view(['DELETE'])
def delete_desparacitacion(request, pet_id, desparacitacion_id):
    try:
        desparacitacion = Desparacitacion.objects.get(id=desparacitacion_id, pet_id=pet_id)
        desparacitacion.delete()
        return Response({"message": "Desparacitacion eliminada exitosamente."}, status=status.HTTP_200_OK)
    except Desparacitacion.DoesNotExist:
        return Response({"error": "Desparacitacion no encontrada."}, status=status.HTTP_404_NOT_FOUND)


from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import Pet, Cirugias

@api_view(['DELETE'])
def delete_cirugia(request, pet_id, cirugia_id):
    try:
        cirugia = Cirugias.objects.get(id=cirugia_id, pet_id=pet_id)
        cirugia.delete()
        return Response({"message": "Cirugia eliminada exitosamente."}, status=status.HTTP_200_OK)
    except Vacunas.DoesNotExist:
        return Response({"error": "Cirugia no encontrada."}, status=status.HTTP_404_NOT_FOUND)













from rest_framework.views import APIView
from rest_framework.response import Response
from .models import CustomUser
from .serializers import CustomUserSerializer

class UsersWithPetsView(APIView):
    def get(self, request):
        users = CustomUser.objects.filter(is_staff=False).prefetch_related('pets__vacunas', 'pets__desparacitaciones', 'pets__cirugias').all()
        serializer = CustomUserSerializer(users, many=True)
        return Response(serializer.data)
    











import json
from django.http import JsonResponse
from .models import Pet
from django.views.decorators.csrf import csrf_exempt

@csrf_exempt  # Si estás en entorno de desarrollo, puedes desactivar CSRF
def add_pet(request):
    if request.method == 'POST':
        try:
            # Cargar los datos del cuerpo de la solicitud
            data = json.loads(request.body)
            
            # Crear una nueva mascota
            pet = Pet.objects.create(
                namepet=data['namepet'],
                especie=data['especie'],
                raza=data.get('raza', ''),  # Raza puede ser opcional
                fecha_nacimientopet=data['fecha_nacimientopet'],
                color=data.get('color', ''),  # Color puede ser opcional
                sexo=data['sexo'],
                owner_id=data['owner'],  # El ID del propietario
            )
            # Retornar una respuesta JSON de éxito
            return JsonResponse({'message': 'Mascota agregada con éxito'}, status=201)
        except Exception as e:
            # En caso de error, retornar mensaje de error
            return JsonResponse({'error': str(e)}, status=400)
    else:
        return JsonResponse({'error': 'Método no permitido'}, status=405)




#class LoginView(generics.GenericAPIView):
 #   queryset = User.objects.all()
  #  serializer_class = LoginSerializer

   # def post(self, request, *args, **kwargs):
    #    username = request.data.get('username')
     #   password = request.data.get('password')

        # Buscar al usuario por nombre de usuario
      #  user = User.objects.filter(username=username).first()

       # if user:
        #    login_attempt, created = LoginAttempt.objects.get_or_create(user=user)

            # Bloqueo de cuenta si se exceden los intentos
         #   if login_attempt.is_locked:
          #      unlock_time = login_attempt.last_attempt + timedelta(minutes=15)
           #     if timezone.now() > unlock_time:
            #        login_attempt.is_locked = False
             #       login_attempt.attempts = 0
              #      login_attempt.save()
               # else:
                #    return Response({
                 #       'error': 'Cuenta bloqueada. Inténtalo más tarde.'
                  #  }, status=status.HTTP_403_FORBIDDEN)

            # Intento de autenticación
            #user_auth = authenticate(username=username, password=password)

            #if user_auth:
                # Si la autenticación es exitosa, restablecer los intentos fallidos
             #   login_attempt.attempts = 0
              #  login_attempt.save()

                # Generar tokens de autenticación
               # refresh = RefreshToken.for_user(user_auth)

                # Obtener los datos del Owner asociado si existe
                #owner = getattr(user_auth, 'owner', None)
                #if owner:
                 #   owner_serializer = OwnerSerializer(owner)
                  #  response_data = {
                   #     'refresh': str(refresh),
                    #    'access': str(refresh.access_token),
                     #   'owner': owner_serializer.data,
                      #  'is_staff': user_auth.is_staff  # Añadir el campo is_staff
                   # }
                    #return Response(response_data, status=status.HTTP_200_OK)

                #response_data = {
                 #   'refresh': str(refresh),
                  #  'access': str(refresh.access_token),
                   # 'message': 'Usuario autenticado, pero no se encontraron datos de propietario.',
                    #'is_staff': user_auth.is_staff  # Añadir el campo is_staff
                #}
                #return Response(response_data, status=status.HTTP_200_OK)

            # Si las credenciales son incorrectas, incrementar el contador de intentos
            #login_attempt.attempts += 1
            #login_attempt.last_attempt = timezone.now()
            #if login_attempt.attempts >= 5:
             #   login_attempt.is_locked = True

            #login_attempt.save()
            #return Response({'error': 'Credenciales incorrectas'}, status=status.HTTP_401_UNAUTHORIZED)

        # Si no se encuentra al usuario, responder con error
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
from rest_framework.response import Response
from rest_framework.decorators import api_view
from rest_framework import status
from django.utils.timezone import now
from .serializers import CustomUserSerializer
from .models import LoginAttempt, CustomUser  # Usamos CustomUser

LOCK_DURATION_MINUTES = 15  # Duración del bloqueo en minutos
MAX_FAILED_ATTEMPTS = 3  # Número máximo de intentos antes de bloquear

@api_view(['POST'])
def login(request):
    """
    Vista para autenticar al usuario y manejar intentos fallidos con bloqueo temporal.
    """
    username = request.data.get('username')
    password = request.data.get('password')

    # Validación básica
    if not username or not password:
        return Response({'detail': 'Faltan credenciales'}, status=status.HTTP_400_BAD_REQUEST)

    # Buscar al usuario usando CustomUser
    try:
        user = CustomUser.objects.get(username=username)
    except CustomUser.DoesNotExist:
        return Response({'detail': 'Credenciales incorrectas'}, status=status.HTTP_401_UNAUTHORIZED)

    # Gestionar intentos de inicio de sesión
    login_attempt, created = LoginAttempt.objects.get_or_create(user=user)

    if login_attempt.is_locked():
        return Response(
            {'detail': f'Usuario bloqueado hasta {login_attempt.lock_until.strftime("%Y-%m-%d %H:%M:%S")}'},
            status=status.HTTP_403_FORBIDDEN
        )

    # Intentar autenticar al usuario
    user = authenticate(username=username, password=password)
    if not user:
        # Incrementar intentos fallidos
        login_attempt.failed_attempts += 1

        if login_attempt.failed_attempts >= MAX_FAILED_ATTEMPTS:
            login_attempt.lock_user(LOCK_DURATION_MINUTES)
            return Response(
                {'detail': f'Usuario bloqueado por {LOCK_DURATION_MINUTES} minutos debido a múltiples intentos fallidos.'},
                status=status.HTTP_403_FORBIDDEN
            )

        login_attempt.save()
        return Response(
            {'detail': 'Credenciales incorrectas. Intente de nuevo.'},
            status=status.HTTP_401_UNAUTHORIZED
        )

    # Autenticación exitosa: resetear intentos
    login_attempt.reset_attempts()

    # Generar tokens JWT
    refresh = RefreshToken.for_user(user)
    access_token = str(refresh.access_token)

    # Serializar datos del usuario
    user_data = CustomUserSerializer(user, context={'request': request}).data

    return Response({
        'access': access_token,
        'refresh': str(refresh),
        'user_type': 'admin' if user.is_staff else 'user',
        'user_data': user_data,  # Aquí están los datos detallados del usuario
    })





from django.core.mail import send_mail
from django.contrib.auth.models import User
from django.utils.crypto import get_random_string
from django.urls import reverse
from django.http import JsonResponse
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny
from django.contrib.auth.models import User
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.core.mail import send_mail
from django.conf import settings

class PasswordResetView(APIView):
    def post(self, request, *args, **kwargs):
        email = request.data.get('email')

        # Verifica si el correo electrónico está presente
        if not email:
            return Response(
                {"detail": "Email is required."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Busca todos los usuarios con el correo electrónico proporcionado
        users = User.objects.filter(email=email)

        if not users.exists():
            return Response(
                {"detail": "No user found with this email address."},
                status=status.HTTP_404_NOT_FOUND
            )

        # Procesa todos los usuarios encontrados
        for user in users:
            # Enviar el correo de restablecimiento de contraseña
            self.send_password_reset_email(user)

        return Response(
            {"detail": "Password reset email(s) sent."},
            status=status.HTTP_200_OK
        )

    def send_password_reset_email(self, user):
        # Crea un token de restablecimiento, por ejemplo usando Django Rest Framework JWT o el sistema de Django
        token = self.generate_reset_token(user)

        # El mensaje del correo de restablecimiento
        reset_link = f"{settings.FRONTEND_URL}/password-reset/{token}/"

        # Lógica para enviar el correo de restablecimiento
        subject = 'Password Reset Request'
        message = f'Please use the following link to reset your password: {reset_link}'
        from_email = settings.DEFAULT_FROM_EMAIL

        send_mail(
            subject,
            message,
            from_email,
            [user.email],
            fail_silently=False,
        )

    def generate_reset_token(self, user):
        # Aquí puedes generar el token de restablecimiento, por ejemplo, usando Django Rest Framework JWT
        # O puedes usar el sistema de restablecimiento de contraseña de Django
        from django.contrib.auth.tokens import default_token_generator
        token = default_token_generator.make_token(user)
        return token
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth.models import User
from django.http import JsonResponse
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth import update_session_auth_hash
from django.core.exceptions import ValidationError
from rest_framework.permissions import AllowAny
from django.conf import settings
from django.contrib.auth.forms import PasswordChangeForm


class PasswordChangeView(APIView):
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        # Extrae el token y la nueva contraseña del request
        token = request.data.get('token')
        new_password = request.data.get('new_password')

        if not token or not new_password:
            return Response(
                {"detail": "Token and new password are required."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Verifica el token
        user = self.get_user_by_token(token)
        if not user:
            return Response(
                {"detail": "Invalid token."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Intenta cambiar la contraseña del usuario
        try:
            self.change_user_password(user, new_password)
        except ValidationError as e:
            return Response(
                {"detail": str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )

        return Response(
            {"detail": "Password successfully changed."},
            status=status.HTTP_200_OK
        )

    def get_user_by_token(self, token):
        """
        Verifica si el token es válido y devuelve el usuario correspondiente.
        """
        try:
            # Verifica si el token es válido usando el token de Django
            user = default_token_generator.check_token(User, token)
            return user
        except Exception:
            return None

    def change_user_password(self, user, new_password):
        """
        Cambia la contraseña del usuario y la guarda.
        """
        user.set_password(new_password)
        user.save()

        # Aquí puedes agregar lógica adicional de validación si lo deseas
        # Por ejemplo, validación de complejidad de contraseñas

        # Si se está usando sesión, actualiza la sesión de autenticación
        update_session_auth_hash(user)







from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from .models import Citas, RegistroDispositivo
from .serializers import CitaSerializer
from datetime import date
from django.db.models import F
from django.core.mail import send_mail
from django.conf import settings
import uuid

def obtener_id_dispositivo(request):
    """
    Obtiene el identificador único del dispositivo desde la cabecera del agente del usuario.
    """
    return request.META.get('HTTP_USER_AGENT', 'Desconocido')

class CitasCreateView(APIView):
    def post(self, request, *args, **kwargs):
        # Obtener el identificador del dispositivo
        dispositivo_id = obtener_id_dispositivo(request)

        # Verificar o crear un registro de dispositivo para el día actual
        registro, created = RegistroDispositivo.objects.get_or_create(
            dispositivo_id=dispositivo_id,
            fecha=date.today(),
            defaults={'conteo': 0}
        )

        # Comprobar si ya alcanzó el límite de 3 registros
        if registro.conteo >= 3:
            return Response(
                {"message": "Solo puedes registrar hasta 3 citas por día desde este dispositivo."},
                status=status.HTTP_429_TOO_MANY_REQUESTS
            )

        # Incrementar el conteo de registros
        registro.conteo = F('conteo') + 1
        registro.save()
        registro.refresh_from_db()  # Asegurar que el conteo actualizado se refleje

        # Serializar y validar los datos de la cita
        serializer = CitaSerializer(data=request.data)
        if serializer.is_valid():
            # Crear la cita inicialmente, pero no validada
            cita = serializer.save(validada=False)

            # Generar un token de validación único
            token_validacion = uuid.uuid4()

            # Actualizar la cita con el token de validación
            cita.token_validacion = token_validacion
            cita.save()

            # Enviar correo de verificación
            self.enviar_correo_verificacion(cita.correocita, token_validacion)

            return Response({"message": "Cita creada. Revisa tu correo para verificar tu cita."}, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def enviar_correo_verificacion(self, correo, token):
        """
        Enviar un correo de verificación con un enlace que incluya el token.
        """
        verification_link = f"http://localhost:8000/api/citas/verificar/{token}/"
        subject = "Verificación de Cita"
        message = f"Por favor, haz clic en el siguiente enlace para verificar tu cita: {verification_link}"
        from_email = settings.DEFAULT_FROM_EMAIL

        send_mail(subject, message, from_email, [correo])




class CitasVerificarView(APIView):
    def get(self, request, token, *args, **kwargs):
        # Buscar la cita por el token de validación
        cita = get_object_or_404(Citas, token_validacion=token)

        # Si la cita ya está validada, devolver un mensaje adecuado
        if cita.validada:
            return Response({"message": "La cita ya ha sido verificada previamente."}, status=status.HTTP_400_BAD_REQUEST)

        # Marcar la cita como validada
        cita.validada = True
        cita.save()

        return Response({"message": "Cita verificada correctamente. Ahora tu cita ha sido agendada."}, status=status.HTTP_200_OK)


# views.py
from django.http import JsonResponse
from .models import Citas

def verificar_fecha(request):
    fecha = request.GET.get('fecha')
    hora = request.GET.get('hora')

    # Verificar si ya existe una cita a esa fecha y hora
    if Citas.objects.filter(fechacita=fecha, horacita=hora).exists():
        return JsonResponse({"existe": True, "mensaje": "Ya hay una cita registrada a esa hora."}, status=400)
    else:
        return JsonResponse({"existe": False, "mensaje": "Hora disponible."}, status=200)




# appointments/views.py

from rest_framework import generics
from .models import Citas
from .serializers import CitaSerializer

class CitasListView(generics.ListAPIView):
    queryset = Citas.objects.filter(validada=True)
    serializer_class = CitaSerializer


from rest_framework import generics
from .models import Citas
from .serializers import CitaSerializer

class CitasListsinView(generics.ListAPIView):
    queryset = Citas.objects.filter(validada=False)  # Filter to only show validated appointments
    serializer_class = CitaSerializer



# appointments/views.py

from rest_framework import generics
from .models import Citas
from .serializers import CitaSerializer

class CitasUpdateView(generics.UpdateAPIView):
    queryset = Citas.objects.all()
    serializer_class = CitaSerializer
    lookup_field = 'id'  


# appointments/views.py

from rest_framework import generics
from .models import Citas
from .serializers import CitaSerializer

class CitasDeleteView(generics.DestroyAPIView):
    queryset = Citas.objects.all()
    serializer_class = CitaSerializer
    lookup_field = 'id'  # Utilizamos 'id' para localizar la cita a eliminar

