# Generated by Django 2.2.4 on 2021-09-19 06:57

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0002_user_is_email_verify'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='user',
            name='is_accountant_agent',
        ),
        migrations.RemoveField(
            model_name='user',
            name='is_education_agent',
        ),
        migrations.RemoveField(
            model_name='user',
            name='is_end_user',
        ),
        migrations.RemoveField(
            model_name='user',
            name='is_migration_agent',
        ),
        migrations.RemoveField(
            model_name='user',
            name='is_natti_translator_agent',
        ),
        migrations.AddField(
            model_name='user',
            name='agent_type',
            field=models.IntegerField(choices=[(1, 1), (2, 2), (3, 3), (4, 4), (5, 5)], default=5),
        ),
        migrations.AddField(
            model_name='user',
            name='is_agent',
            field=models.BooleanField(default=False),
        ),
    ]
