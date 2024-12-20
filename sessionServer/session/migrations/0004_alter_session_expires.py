# Generated by Django 5.1.2 on 2024-11-20 18:47

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('session', '0003_alter_session_expires'),
    ]

    operations = [
        migrations.AlterField(
            model_name='session',
            name='expires',
            field=models.DateTimeField(default=datetime.datetime(2024, 11, 20, 20, 47, 32, 351683, tzinfo=datetime.timezone.utc), editable=False, help_text='The timestamp when this session will expire\\.'),
        ),
    ]
