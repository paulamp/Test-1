# Generated by Django 2.0.10 on 2019-05-06 20:03

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0009_collaboratordocument_timestamp'),
    ]

    operations = [
        migrations.AddField(
            model_name='collaboratordocument',
            name='status',
            field=models.CharField(default='Pending', max_length=44),
        ),
    ]