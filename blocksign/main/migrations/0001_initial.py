# Generated by Django 2.0.10 on 2019-03-19 11:52

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('auth', '0009_alter_user_last_name_max_length'),
    ]

    operations = [
        migrations.CreateModel(
            name='SignUser',
            fields=[
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, primary_key=True, serialize=False, to=settings.AUTH_USER_MODEL)),
                ('address', models.CharField(max_length=42)),
                ('passphrase', models.CharField(default='aabbcc11', max_length=30)),
                ('avatar', models.ImageField(blank=True, null=True, upload_to='user_%Y_%m')),
            ],
        ),
    ]
