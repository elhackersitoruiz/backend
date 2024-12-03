# Generated by Django 5.1.2 on 2024-12-01 04:57

import django.contrib.auth.models
import django.contrib.auth.validators
import django.core.validators
import django.db.models.deletion
import django.utils.timezone
import tasks.models
import uuid
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('auth', '0012_alter_user_first_name_max_length'),
    ]

    operations = [
        migrations.CreateModel(
            name='Citas',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('namecita', models.CharField(max_length=100, verbose_name='Nombre')),
                ('correocita', models.EmailField(max_length=100, verbose_name='Correo')),
                ('celularcita', models.CharField(max_length=9, validators=[tasks.models.validate_celular], verbose_name='Celular')),
                ('serviciocita', models.CharField(choices=[('CONSULTA', 'Consulta Médica'), ('VACUNACION', 'Vacunación'), ('CIRUGIAS', 'Cirugías'), ('ESTETICA', 'Estética')], max_length=20, verbose_name='Servicio')),
                ('fechacita', models.DateField(verbose_name='Fecha de la Cita')),
                ('horacita', models.CharField(choices=[('11:00 AM', '11:00 AM'), ('11:30 AM', '11:30 AM'), ('12:00 PM', '12:00 PM'), ('12:30 PM', '12:30 PM'), ('01:00 PM', '01:00 PM'), ('01:30 PM', '01:30 PM'), ('02:00 PM', '02:00 PM'), ('02:30 PM', '02:30 PM'), ('03:00 PM', '03:00 PM'), ('03:30 PM', '03:30 PM'), ('04:00 PM', '04:00 PM'), ('04:30 PM', '04:30 PM'), ('05:00 PM', '05:00 PM'), ('05:30 PM', '05:30 PM'), ('06:00 PM', '06:00 PM'), ('06:30 PM', '06:30 PM')], max_length=10, verbose_name='Hora de la cita')),
                ('mensajecita', models.TextField(blank=True, max_length=500, verbose_name='Mensaje')),
                ('token_validacion', models.UUIDField(default=uuid.uuid4, editable=False, unique=True)),
                ('validada', models.BooleanField(default=False)),
                ('created_at', models.DateTimeField(auto_now_add=True, verbose_name='Fecha de creación')),
                ('updated_at', models.DateTimeField(auto_now=True, verbose_name='Última modificación')),
            ],
        ),
        migrations.CreateModel(
            name='RegistroDispositivo',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('dispositivo_id', models.CharField(max_length=255, verbose_name='ID del Dispositivo')),
                ('fecha', models.DateField(default=django.utils.timezone.now, verbose_name='Fecha del Registro')),
                ('conteo', models.PositiveIntegerField(default=0, verbose_name='Cantidad de Registros')),
            ],
        ),
        migrations.CreateModel(
            name='CustomUser',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('password', models.CharField(max_length=128, verbose_name='password')),
                ('last_login', models.DateTimeField(blank=True, null=True, verbose_name='last login')),
                ('is_superuser', models.BooleanField(default=False, help_text='Designates that this user has all permissions without explicitly assigning them.', verbose_name='superuser status')),
                ('username', models.CharField(error_messages={'unique': 'A user with that username already exists.'}, help_text='Required. 150 characters or fewer. Letters, digits and @/./+/-/_ only.', max_length=150, unique=True, validators=[django.contrib.auth.validators.UnicodeUsernameValidator()], verbose_name='username')),
                ('first_name', models.CharField(blank=True, max_length=150, verbose_name='first name')),
                ('last_name', models.CharField(blank=True, max_length=150, verbose_name='last name')),
                ('email', models.EmailField(blank=True, max_length=254, verbose_name='email address')),
                ('is_staff', models.BooleanField(default=False, help_text='Designates whether the user can log into this admin site.', verbose_name='staff status')),
                ('is_active', models.BooleanField(default=True, help_text='Designates whether this user should be treated as active. Unselect this instead of deleting accounts.', verbose_name='active')),
                ('date_joined', models.DateTimeField(default=django.utils.timezone.now, verbose_name='date joined')),
                ('direccion', models.CharField(max_length=255, verbose_name='Dirección')),
                ('telefono', models.CharField(max_length=9, validators=[django.core.validators.RegexValidator(message="El número de teléfono debe comenzar con '9' y tener exactamente 9 dígitos.", regex='^9\\d{8}$')], verbose_name='Teléfono')),
                ('dni', models.CharField(max_length=20, unique=True, verbose_name='DNI')),
                ('groups', models.ManyToManyField(blank=True, help_text='The groups this user belongs to. A user will get all permissions granted to each of their groups.', related_name='user_set', related_query_name='user', to='auth.group', verbose_name='groups')),
                ('user_permissions', models.ManyToManyField(blank=True, help_text='Specific permissions for this user.', related_name='user_set', related_query_name='user', to='auth.permission', verbose_name='user permissions')),
            ],
            options={
                'verbose_name': 'user',
                'verbose_name_plural': 'users',
                'abstract': False,
            },
            managers=[
                ('objects', django.contrib.auth.models.UserManager()),
            ],
        ),
        migrations.CreateModel(
            name='Pet',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('namepet', models.CharField(max_length=100, verbose_name='Nombre de la Mascota')),
                ('especie', models.CharField(max_length=50, verbose_name='Especie')),
                ('raza', models.CharField(max_length=50, verbose_name='Raza')),
                ('fecha_nacimientopet', models.DateField(validators=[tasks.models.validate_birthdate], verbose_name='Fecha de Nacimiento')),
                ('color', models.CharField(max_length=50, verbose_name='Color')),
                ('sexo', models.CharField(choices=[('M', 'Male'), ('F', 'Female')], max_length=1, verbose_name='Sexo')),
                ('owner', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='pets', to=settings.AUTH_USER_MODEL, verbose_name='Dueño')),
            ],
        ),
        migrations.CreateModel(
            name='Desparacitacion',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('producto', models.CharField(max_length=50, verbose_name='Producto de Desparacitación')),
                ('fechadespara', models.DateField(verbose_name='Fecha de Desparacitación')),
                ('peso', models.DecimalField(decimal_places=2, max_digits=5, verbose_name='Peso')),
                ('proxima', models.DateField(verbose_name='Próxima Desparacitación')),
                ('pet', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='desparacitaciones', to='tasks.pet')),
            ],
        ),
        migrations.CreateModel(
            name='Cirugias',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('fechaciru', models.DateField(verbose_name='Fecha de la Cirugía')),
                ('fechareti', models.DateField(verbose_name='Fecha de Retiro')),
                ('tipo', models.CharField(max_length=50, verbose_name='Tipo de Cirugía')),
                ('pet', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='cirugias', to='tasks.pet')),
            ],
        ),
        migrations.CreateModel(
            name='Vacunas',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('fechavacuna', models.DateField(verbose_name='Fecha de Vacunación')),
                ('fecharevacuna', models.DateField(verbose_name='Fecha de Revacunación')),
                ('tipo', models.CharField(max_length=50, verbose_name='Tipo de Vacuna')),
                ('descripcion', models.CharField(max_length=50, verbose_name='Descripción')),
                ('pet', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='vacunas', to='tasks.pet')),
            ],
        ),
    ]
