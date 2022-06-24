import ast

from django.conf import settings
from django.core.mail import EmailMessage
from django.template.loader import render_to_string

from users.models import UserPersonalInformation


def email_users(user, subject, template, domain):

    subject = subject
    message = render_to_string(template, {
        'user': user,
        'domain': domain,
        'email': user.email,
    })
    to_email = user.email

    email = EmailMessage(
        subject, message, to=[to_email], from_email=settings.EMAIL_FROM
    )
    email.content_subtype = 'html'
    email.send()


def get_agent_status(user_id):
    try:
        profile = UserPersonalInformation.objects.get(user_id=user_id)
        return profile.is_profile_complete, profile.status
    except UserPersonalInformation.DoesNotExist as e:
        return None, None
