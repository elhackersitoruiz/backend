from django.db import models
from django.core.exceptions import ValidationError
from django.core.validators import RegexValidator
from datetime import date
from django.db import models
from django.core.validators import RegexValidator
from django.core.exceptions import ValidationError
from django.contrib.auth.models import AbstractUser

class CustomUser(AbstractUser):
    direccion = models.CharField(max_length=255, verbose_name="Dirección")
    telefono = models.CharField(
        max_length=9,
        validators=[
            RegexValidator(
                regex=r'^9\d{8}$',
                message="El número de teléfono debe comenzar con '9' y tener exactamente 9 dígitos."
            )
        ],
        verbose_name="Teléfono"
    )
    dni = models.CharField(
        max_length=20,
        unique=True,
        verbose_name="DNI"
    )

    def clean(self):
        super().clean()
        # Validación personalizada para `dni`
        if not self.dni.isdigit() or len(self.dni) < 8:
            raise ValidationError("El DNI debe contener solo dígitos y tener al menos 8 caracteres.")

    def __str__(self):
        return self.username

    


def validate_birthdate(value):
    if value > date.today():
        raise ValidationError("La fecha de nacimiento no puede ser futura.")

class Pet(models.Model):
    SEXO_CHOICES = [
        ('M', 'Male'),
        ('F', 'Female'),
    ]

    namepet = models.CharField(max_length=100, verbose_name="Nombre de la Mascota")
    especie = models.CharField(max_length=50, verbose_name="Especie")
    raza = models.CharField(max_length=50, verbose_name="Raza")
    fecha_nacimientopet = models.DateField(verbose_name="Fecha de Nacimiento", validators=[validate_birthdate])
    color = models.CharField(max_length=50, verbose_name="Color")
    sexo = models.CharField(max_length=1, choices=SEXO_CHOICES, verbose_name="Sexo")
    owner = models.ForeignKey('CustomUser', related_name='pets', on_delete=models.CASCADE, verbose_name="Dueño")

    def __str__(self):
        return f"{self.namepet} ({self.owner.username})"


class Vacunas(models.Model):
    pet = models.ForeignKey(Pet, on_delete=models.CASCADE, related_name="vacunas")
    fechavacuna = models.DateField(verbose_name="Fecha de Vacunación")
    fecharevacuna = models.DateField(verbose_name="Fecha de Revacunación")
    tipo = models.CharField(max_length=50, verbose_name="Tipo de Vacuna")
    descripcion = models.CharField(max_length=50, verbose_name="Descripción")

    def __str__(self):
        return f"{self.pet.namepet} - {self.tipo}"

class Desparacitacion(models.Model):
    pet = models.ForeignKey(Pet, on_delete=models.CASCADE, related_name="desparacitaciones")
    producto = models.CharField(max_length=50, verbose_name="Producto de Desparacitación")
    fechadespara = models.DateField(verbose_name="Fecha de Desparacitación")
    peso = models.DecimalField(max_digits=5, decimal_places=2, verbose_name="Peso")
    proxima = models.DateField(verbose_name="Próxima Desparacitación")

    def __str__(self):
        return f"{self.pet.namepet} - {self.producto}"

class Cirugias(models.Model):
    pet = models.ForeignKey(Pet, on_delete=models.CASCADE, related_name="cirugias")
    fechaciru = models.DateField(verbose_name="Fecha de la Cirugía")
    fechareti = models.DateField(verbose_name="Fecha de Retiro")
    tipo = models.CharField(max_length=50, verbose_name="Tipo de Cirugía")

    def __str__(self):
        return f"{self.pet.namepet} - {self.tipo}"


from django.db import models
from django.core.exceptions import ValidationError
import uuid
from datetime import datetime, timedelta
import re

# Función para generar las opciones de hora
def generate_hour_choices(start="11:00", end="18:30", interval=30):
    start_time = datetime.strptime(start, "%H:%M")
    end_time = datetime.strptime(end, "%H:%M")
    choices = []
    while start_time <= end_time:
        formatted_time = start_time.strftime("%I:%M %p")
        choices.append((formatted_time, formatted_time))
        start_time += timedelta(minutes=interval)
    return choices

# Validador personalizado para el celular
def validate_celular(value):
    # Asegurarse de que el número comienza con "9" y tiene exactamente 9 dígitos
    if not re.match(r'^9\d{8}$', value):
        raise ValidationError("El número de celular debe comenzar con 9 y tener exactamente 9 dígitos.")

class Citas(models.Model):
    SERVICIO_CHOICES = [
        ('CONSULTA', 'Consulta Médica'),
        ('VACUNACION', 'Vacunación'),
        ('CIRUGIAS', 'Cirugías'),
        ('ESTETICA', 'Estética'),
    ]
    
    HORA_CHOICES = generate_hour_choices()

    namecita = models.CharField(max_length=100, verbose_name="Nombre")
    correocita = models.EmailField(max_length=100, verbose_name="Correo")
    celularcita = models.CharField(max_length=9, verbose_name="Celular", validators=[validate_celular])
    serviciocita = models.CharField(max_length=20, choices=SERVICIO_CHOICES, verbose_name="Servicio")
    fechacita = models.DateField(verbose_name="Fecha de la Cita")
    horacita = models.CharField(max_length=10, choices=HORA_CHOICES, verbose_name="Hora de la cita")
    mensajecita = models.TextField(max_length=500, verbose_name="Mensaje", blank=True)
    token_validacion = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    validada = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True, verbose_name="Fecha de creación")
    updated_at = models.DateTimeField(auto_now=True, verbose_name="Última modificación")

    def clean(self):
        super().clean()
        # Verificar si ya existe una cita agendada para la misma fecha y hora
        if Citas.objects.filter(fechacita=self.fechacita, horacita=self.horacita).exists():
            raise ValidationError("Ya existe una cita agendada para esta fecha y hora.")

    def __str__(self):
        return f"{self.namecita} - {self.fechacita} - {self.horacita}"
    
from django.db import models
from django.utils.timezone import now

class RegistroDispositivo(models.Model):
    dispositivo_id = models.CharField(max_length=255, verbose_name="ID del Dispositivo")
    fecha = models.DateField(default=now, verbose_name="Fecha del Registro")
    conteo = models.PositiveIntegerField(default=0, verbose_name="Cantidad de Registros")

    def __str__(self):
        return f"{self.dispositivo_id} - {self.fecha} - {self.conteo}"
    



    
from django.db import models
from django.utils.timezone import now, timedelta
from django.contrib.auth import get_user_model

User = get_user_model()

class LoginAttempt(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="login_attempt")
    failed_attempts = models.IntegerField(default=0, verbose_name="Intentos fallidos")
    lock_until = models.DateTimeField(null=True, blank=True, verbose_name="Bloqueado hasta")

    def is_locked(self):
        """
        Verifica si el usuario está bloqueado.
        """
        return self.lock_until and self.lock_until > now()

    def lock_user(self, lock_duration):
        """
        Bloquea al usuario por un tiempo definido.
        """
        self.lock_until = now() + timedelta(minutes=lock_duration)
        self.failed_attempts = 0  # Reinicia los intentos al bloquear
        self.save()

    def reset_attempts(self):
        """
        Reinicia el contador de intentos fallidos y elimina el bloqueo.
        """
        self.failed_attempts = 0
        self.lock_until = None
        self.save()


