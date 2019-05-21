# Generated by Django 2.0.10 on 2019-03-19 11:53

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='Document',
            fields=[
                ('hash', models.CharField(max_length=66, primary_key=True, serialize=False)),
                ('name', models.CharField(max_length=200)),
                ('tx_id', models.CharField(max_length=66, unique=True)),
                ('status', models.CharField(default='Pending', max_length=44)),
                ('minter', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='main.SignUser')),
            ],
        ),
    ]