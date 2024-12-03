from datetime import date
from django.forms import ValidationError
from rest_framework import serializers
from .models import  Pet, Cirugias, Vacunas, Desparacitacion, Citas


class CitaSerializer(serializers.ModelSerializer):
    class Meta:
        model = Citas
        fields = '__all__'

class DesparacitacionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Desparacitacion
        fields = ['id', 'pet', 'producto', 'fechadespara', 'peso', 'proxima']


class VacunasSerializer(serializers.ModelSerializer):
    class Meta:
        model = Vacunas
        fields = ['id', 'pet', 'fechavacuna', 'fecharevacuna', 'tipo', 'descripcion']

class CirugiasSerializer(serializers.ModelSerializer):
    class Meta:
        model = Cirugias
        fields = ['id', 'pet', 'fechaciru', 'fechareti', 'tipo']






# serializers.py


from rest_framework import serializers
from .models import CustomUser, Pet

class PetSerializer(serializers.ModelSerializer):
    owner = serializers.PrimaryKeyRelatedField(queryset=CustomUser.objects.all(), required=False)
    vacunas = VacunasSerializer(many=True, read_only=True)
    desparacitaciones = DesparacitacionSerializer(many=True, read_only=True)
    cirugias = CirugiasSerializer(many=True, read_only=True)

    class Meta:
        model = Pet
        fields = [
            'id',
            'namepet',
            'especie',
            'raza',
            'fecha_nacimientopet',
            'color',
            'sexo',
            'owner',
            'vacunas',
            'desparacitaciones',
            'cirugias',
        ]

    def create(self, validated_data):
        # Si no se proporciona un owner, se asocia al usuario autenticado
        if not validated_data.get('owner'):
            validated_data['owner'] = self.context['request'].user
        
        return Pet.objects.create(**validated_data)



# Serializador para el usuario
from rest_framework import serializers
from django.contrib.auth.password_validation import validate_password
from .models import CustomUser  # o el modelo de usuario que estés utilizando
class CustomUserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True)
    pets = PetSerializer(many=True, read_only=True)  # Incluye las mascotas asociadas.

    class Meta:
        model = CustomUser
        fields = [
            'id',
            'username',
            'email',
            'first_name',
            'last_name',
            'telefono',
            'direccion',
            'dni',
            'password',
            'is_staff',
            'pets',
        ]

    def validate_password(self, value):
        # Valida la contraseña utilizando el validador de Django
        validate_password(value)
        return value

    def create(self, validated_data):
        password = validated_data.pop('password')
        user = CustomUser.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            first_name=validated_data.get('first_name', ''),
            last_name=validated_data.get('last_name', ''),
            telefono=validated_data.get('telefono', ''),
            direccion=validated_data.get('direccion', ''),
            dni=validated_data.get('dni', ''),
            password=password,  # Crea el usuario con la contraseña
            is_staff=validated_data.get('is_staff', False),
        )
        return user













