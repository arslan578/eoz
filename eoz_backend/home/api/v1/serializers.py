import json

from allauth.account.adapter import get_adapter
from allauth.utils import generate_unique_username, email_address_exists
from django.conf import settings
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.http import HttpRequest
from allauth.account import app_settings as allauth_settings
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.utils.translation import gettext_lazy as _
from allauth.account.models import EmailAddress

from home.models import AgentServices, ClientServiceReview, Order, AgentBalance, ChatFilter
from users.models import UserPersonalInformation
from chats.models import ChatRoom

User = get_user_model()


class SignupModelSerializer(serializers.ModelSerializer):

    class Meta:
        model = User
        fields = ('id', 'email', 'password', 'is_active', 'agent_type', 'is_agent')
        extra_kwargs = {
            'password': {
                'write_only': True,
                'style': {
                    'input_type': 'password'
                }
            },
            'email': {
                'required': True,
                'allow_blank': False,
            }
        }

    def _get_request(self):
        request = self.context.get('request')
        if request and not isinstance(request, HttpRequest) and hasattr(request, '_request'):
            request = request._request
        return request

    def validate_email(self, email):
        email = get_adapter().clean_email(email)
        if allauth_settings.UNIQUE_EMAIL:
            if email and email_address_exists(email):
                raise serializers.ValidationError(
                    _("A user is already registered with this e-mail address."))
        return email

    def create(self, validated_data):
        user = User(
            email=validated_data.get('email'),
            username=generate_unique_username([
                validated_data.get('first_name'),
                validated_data.get('email'),
                'user'
            ]),
            is_agent=validated_data.get('is_agent')
        )
        user.set_password(validated_data.get('password'))
        user.save()
        try:
            email_address_obj = EmailAddress.objects.get(
                user=user
            )
            email_address_obj.verified = False

        except EmailAddress.DoesNotExist:
            email_address_obj = EmailAddress(
                user=user, email=user.email, verified=False, primary=True
            )

        email_address_obj.save()
        token_generator = PasswordResetTokenGenerator()
        temp_key = token_generator.make_token(user)
        url = "{url}/confirm-email/{uid}/{temp_key}".format(
            url=settings.FRONTEND_HOST, temp_key=temp_key, uid=urlsafe_base64_encode(force_bytes(user.pk)))

        from .utils import email_users
        email_users(user, '[EOZ] Confirm your email address', 'account/account_activation_email.txt', url)

        return user

    def save(self, request=None):
        """rest_auth passes request so we must override to accept it"""
        return super().save()


class UserModelSerializer(serializers.ModelSerializer):

    class Meta:
        model = User
        fields = ('id', 'email', 'is_active', 'agent_type', 'is_agent', 'first_name', 'last_name')


class ClientModelSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'first_name', 'last_name']


class VerifyPhoneNumberSerializer(serializers.Serializer):
    verification_code = serializers.CharField(max_length=4, required=True)

    def validate_verify_code(self, value):
        if not value:
            raise serializers.ValidationError('This field is required.')
        return value


class AgentPersonalInformationModelSerializer(serializers.ModelSerializer):
    agent_type = serializers.SerializerMethodField()
    agent_email = serializers.SerializerMethodField()
    last_login = serializers.SerializerMethodField()
    profile_picture_url = serializers.SerializerMethodField()

    class Meta:
        model = UserPersonalInformation
        exclude = ['created_at', 'updated_at']

    def get_agent_type(self, obj):
        return obj.user.agent_type

    def get_agent_email(self, obj):
        return obj.user.email

    def get_last_login(self, obj):
        return obj.user.updated_at

    def get_profile_picture_url(self, obj):
        try:
            if obj.profile_picture.url:
                return settings.BACKEND_URL + obj.profile_picture.url
            return ''
        except Exception as e:
            return ''


class AgentStatusSerializer(serializers.Serializer):
    status = serializers.CharField(max_length=16, required=True)
    agent_id = serializers.IntegerField(required=True)


class AgentServiceModelSerializer(serializers.ModelSerializer):
    class Meta:
        model = AgentServices
        exclude = ['created_at', 'updated_at']


class SingleUserPersonalInformationModelSerializer(serializers.ModelSerializer):
    profile_picture = serializers.SerializerMethodField()

    class Meta:
        model = UserPersonalInformation
        fields = ['id', 'first_name', 'last_name', 'nationality', 'street_address', 'city', 'state', 'country', 'profile_picture',
                  'description', 'headline']

    def get_profile_picture(self, obj):
        request = self.context.get('request')
        photo_url = obj.profile_picture.url
        return request.build_absolute_uri(photo_url)


class FilterAgentServiceModelSerializer(serializers.ModelSerializer):
    agent_details = serializers.SerializerMethodField()
    average_rate = serializers.SerializerMethodField()

    class Meta:
        model = AgentServices
        exclude = ['created_at', 'updated_at']

    def get_agent_details(self, obj):
        agent = UserPersonalInformation.objects.get(user=obj.user)
        request = self.context.get('request')
        return SingleUserPersonalInformationModelSerializer(agent, context={'request': request}).data

    def get_average_rate(self, obj):
        rate = ClientServiceReview.objects.filter(service=obj).values('rate')

        if len(rate) <= 0:
            return 0

        return round(sum([x['rate'] for x in rate]) / len(rate), 1)


class ClientServiceReviewModelSerializer(serializers.ModelSerializer):
    class Meta:
        model = ClientServiceReview
        exclude = ['created_at', 'updated_at']


class ChatRoomModelSerializer(serializers.ModelSerializer):
    group_name = serializers.SerializerMethodField()

    class Meta:
        model = ChatRoom
        exclude = ['created_at', 'group']

    def get_group_name(self, obj):
        return obj.group.group


class ChangeEmailModelSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ("email", "phone_number")


    @property
    def errors(self):
        """Return an ErrorDict for the data provided for the form."""
        if self._errors is None:
            self.full_clean()
        return self._errors['email']


class OrderModelSerializer(serializers.ModelSerializer):
    agent_name = serializers.SerializerMethodField()
    service_name = serializers.SerializerMethodField()
    client_name = serializers.SerializerMethodField()

    class Meta:
        model = Order
        exclude = ['updated_at']

    def get_agent_name(self, obj):
        try:
            agent = UserPersonalInformation.objects.get(user=obj.agent)
            return agent.first_name
        except UserPersonalInformation.DoesNotExist:
            return ''

    def get_service_name(self, obj):
        return obj.service.category

    def get_client_name(self, obj):
        return obj.client.first_name + " " + obj.client.last_name


class ClientStripeSerializer(serializers.Serializer):
    card_token = serializers.CharField(max_length=256, required=True)
    amount = serializers.IntegerField(required=True)
    service = serializers.IntegerField(required=True)
    agent = serializers.IntegerField(required=True)


class AgentBalanceModelSerializer(serializers.ModelSerializer):
    class Meta:
        model = AgentBalance
        exclude = ['created_at', 'updated_at', 'agent']


class ChatFilterModelSerializer(serializers.ModelSerializer):

    class Meta:
        model = ChatFilter
        exclude = ['created_at', 'updated_at']