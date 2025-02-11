# Generated by Django 5.1.2 on 2025-01-17 10:15

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('session', '0007_temporarytoken_path_alter_server_name_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='session',
            name='expires',
            field=models.DateTimeField(default=datetime.datetime(2025, 1, 17, 12, 15, 5, 136256, tzinfo=datetime.timezone.utc), editable=False, help_text='The timestamp when this session will expire\\.', verbose_name='Session expiry'),
        ),
        migrations.AlterField(
            model_name='temporarytoken',
            name='expires_at',
            field=models.DateTimeField(default=datetime.datetime(2025, 1, 17, 10, 17, 5, 136887, tzinfo=datetime.timezone.utc), editable=False, help_text='The timestamp when this token will expire\\.', verbose_name='Temporary Token expiry'),
        ),
        migrations.AlterField(
            model_name='temporarytoken',
            name='path',
            field=models.CharField(editable=False, help_text='Path of the request.', max_length=128, verbose_name='path'),
        ),
    ]
