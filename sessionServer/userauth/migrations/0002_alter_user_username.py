# Generated by Django 5.1.2 on 2024-11-14 14:07

import userauth.validators
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('userauth', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='username',
            field=models.CharField(max_length=60, unique=True, validators=[userauth.validators.UsernameValidator()], verbose_name='Username'),
        ),
    ]
