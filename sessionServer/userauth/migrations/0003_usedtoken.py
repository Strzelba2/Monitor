# Generated by Django 5.1.2 on 2024-11-26 09:06

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('userauth', '0002_alter_user_username'),
    ]

    operations = [
        migrations.CreateModel(
            name='UsedToken',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('token', models.CharField(editable=False, help_text='The unique token associated with the user.', max_length=255, unique=True, verbose_name='Token')),
                ('used_at', models.DateTimeField(auto_now_add=True, help_text='The timestamp when this token was used.', verbose_name='Used At')),
                ('user', models.ForeignKey(editable=False, help_text='The user who used this token.', on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL, verbose_name='User')),
            ],
            options={
                'verbose_name': 'Used Token',
                'verbose_name_plural': 'Used Tokens',
                'ordering': ['-used_at'],
            },
        ),
    ]
