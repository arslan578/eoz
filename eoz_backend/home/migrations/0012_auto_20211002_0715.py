# Generated by Django 2.2.4 on 2021-10-02 07:15

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('home', '0011_auto_20210929_1416'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='agentservices',
            options={'ordering': ('-created_at',)},
        ),
    ]
