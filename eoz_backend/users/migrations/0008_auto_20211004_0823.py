# Generated by Django 2.2.4 on 2021-10-04 08:23

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0007_auto_20211002_0715'),
    ]

    operations = [
        migrations.AlterField(
            model_name='userpersonalinformation',
            name='status',
            field=models.CharField(choices=[('suspend', 'suspend'), ('pending', 'pending'), ('active', 'active')], default='pending', max_length=16),
        ),
    ]