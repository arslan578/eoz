# Generated by Django 2.2.4 on 2021-09-10 14:59

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('home', '0005_auto_20210910_1455'),
    ]

    operations = [
        migrations.AlterField(
            model_name='order',
            name='status',
            field=models.CharField(choices=[('pending', 'pending'), ('active', 'active'), ('closed', 'closed')], default='pending', max_length=16),
        ),
    ]
