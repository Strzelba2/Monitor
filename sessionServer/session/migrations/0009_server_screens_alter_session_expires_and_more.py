# Generated by Django 5.1.2 on 2025-01-28 22:38

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('session', '0008_alter_session_expires_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='server',
            name='screens',
            field=models.IntegerField(default=1, help_text='Indicates how many screens server have.', verbose_name='Screens'),
        ),
        migrations.AlterField(
            model_name='session',
            name='expires',
            field=models.DateTimeField(default=datetime.datetime(2025, 1, 29, 0, 38, 42, 760650, tzinfo=datetime.timezone.utc), editable=False, help_text='The timestamp when this session will expire\\.', verbose_name='Session expiry'),
        ),
        migrations.AlterField(
            model_name='temporarytoken',
            name='expires_at',
            field=models.DateTimeField(default=datetime.datetime(2025, 1, 28, 22, 40, 42, 761264, tzinfo=datetime.timezone.utc), editable=False, help_text='The timestamp when this token will expire\\.', verbose_name='Temporary Token expiry'),
        ),
    ]
