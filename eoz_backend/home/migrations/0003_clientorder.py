# Generated by Django 2.2.4 on 2021-09-10 14:30

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('home', '0002_clientservicereview'),
    ]

    operations = [
        migrations.CreateModel(
            name='ClientOrder',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('price', models.IntegerField()),
                ('status', models.CharField(choices=[('pending', 'pending'), ('active', 'active'), ('closed', 'closed')], max_length=16)),
                ('is_paid', models.BooleanField(default=False)),
                ('created_at', models.DateField(auto_now_add=True)),
                ('updated_at', models.DateField(auto_now=True)),
                ('agent_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='agent_service_fee', to=settings.AUTH_USER_MODEL)),
                ('client_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='client_paid_fee', to=settings.AUTH_USER_MODEL)),
                ('service', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='home.AgentServices')),
            ],
        ),
    ]