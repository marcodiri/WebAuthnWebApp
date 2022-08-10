# Generated by Django 4.1 on 2022-08-10 07:55

import django.contrib.auth.validators
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='TempSession',
            fields=[
                ('password', models.CharField(max_length=128, verbose_name='password')),
                ('last_login', models.DateTimeField(blank=True, null=True, verbose_name='last login')),
                ('id', models.UUIDField(editable=False, primary_key=True, serialize=False)),
                ('username', models.CharField(max_length=10, unique=True, validators=[django.contrib.auth.validators.ASCIIUsernameValidator])),
            ],
            options={
                'abstract': False,
            },
        ),
    ]
