from django.db import models
from django.contrib.auth.models import AbstractUser
from datetime import datetime
from django.utils.translation import gettext_lazy as _

# Create your models here.

AGENT_TYPE = (
    (1, 1),  # education_agen
    (2, 2),  # migration_agent
    (3, 3),  # accountant_agent
    (4, 4),  # natti_translator_agent
    (5, 5),  # none
)


class User(AbstractUser):
    phone_number = models.CharField(max_length=24, null=True, blank=True)
    is_phone_number_verify = models.BooleanField(default=False)
    agent_type = models.IntegerField(choices=AGENT_TYPE, default=5)
    is_agent = models.BooleanField(default=False)
    is_active = models.BooleanField(default=False)
    is_email_verify = models.BooleanField(default=False)
    is_deleted = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


AGENT_STATUS = (
    ("suspend", "suspend"),
    ("pending", "pending"),
    ("active", "active")

)


class UserPersonalInformation(models.Model):
    first_name = models.CharField(max_length=64, default='')
    last_name = models.CharField(max_length=64, default='')
    date_of_birth = models.DateField()
    nationality = models.CharField(max_length=64, default='')
    street_address = models.TextField(default='')
    city = models.CharField(max_length=32, default='')
    state = models.CharField(max_length=32, default='')
    zip_code = models.CharField(max_length=16, default='')
    country = models.CharField(max_length=32,  default='')
    profile_picture = models.FileField(upload_to='profile_pictures/', default='')
    headline = models.CharField(max_length=72, null=True, default='')
    description = models.CharField(max_length=600, default='')
    offer_online = models.BooleanField(default=False)
    offer_offline = models.BooleanField(default=False)
    client_city = models.CharField(max_length=32, default='')
    client_state = models.CharField(max_length=32, default='')
    client_zip_code = models.CharField(max_length=16, default='')
    client_country = models.CharField(max_length=32, default='')
    client_street_address = models.TextField(default='')
    languages = models.TextField(default='')
    # Education Agent
    education_agent = models.BooleanField(default=False)
    queac_number = models.CharField(max_length=32, default='')
    education_agent_certificate = models.FileField(upload_to='education_agent_certificates/', default='')
    education_agent_experience = models.IntegerField(default=0)

    # Migration Agent
    marn_number = models.CharField(max_length=32, default='')
    migration_agent_certificate = models.FileField(upload_to='migration_agent_certificates/', default='')
    migration_agent_experience = models.IntegerField(default=0)

    # Naati Agent
    naati_certificate = models.FileField(upload_to='naati_certificates/', default='')
    naati_experience = models.IntegerField(default=0)

    # Accountant Agent
    account_agent_experience = models.IntegerField(default=0)

    # Verifications
    australian_nation_id = models.FileField(upload_to='australian_nation_id/', default='')
    utility_bill = models.FileField(upload_to='utility_bill/', default='')
    user = models.OneToOneField(User, on_delete=models.CASCADE, default='')
    status = models.CharField(max_length=16, choices=AGENT_STATUS, default="pending")
    is_profile_complete = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ('-created_at',)
