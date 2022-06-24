import datetime

from allauth.account.models import EmailAddress
from allauth.utils import generate_unique_username
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.db.models import Q
from django.utils.encoding import force_text, force_bytes
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from rest_framework import status
from rest_framework.authentication import TokenAuthentication
from rest_framework.authtoken.models import Token
from rest_framework.decorators import action
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from django.utils.translation import gettext_lazy as _
from django.shortcuts import get_object_or_404
from authy.api import AuthyApiClient
import stripe
import uuid
from rest_framework.viewsets import (
    ModelViewSet,
    ViewSet,
)

from home.api.v1.serializers import (
    SignupModelSerializer, VerifyPhoneNumberSerializer, AgentPersonalInformationModelSerializer, AgentStatusSerializer,
    AgentServiceModelSerializer, FilterAgentServiceModelSerializer, ClientServiceReviewModelSerializer,
    ClientModelSerializer, ChatRoomModelSerializer, ChangeEmailModelSerializer, OrderModelSerializer,
    ClientStripeSerializer, AgentBalanceModelSerializer, UserModelSerializer,

)
from home.api.v1.utils import (
    email_users, get_agent_status
)
from home.models import AgentServices, ClientServiceReview, Order, StripePayment, AgentBalance, ChatFilter
from users.models import UserPersonalInformation
from chats.models import ChatRoom, ChatGroup
from users.permissions import AdminPermission, AllAgentPermission, ClientPermission

User = get_user_model()
Authy = AuthyApiClient(settings.AUTHY_API_KEY)
stripe.api_key = settings.STRIPE_KEY


class SignUpModelViewSet(ModelViewSet):
    serializer_class = SignupModelSerializer
    http_allow_methods = ['POST', ]
    permission_classes = (AllowAny,)
    queryset = User.objects.all()


class ClientSignUpModelViewSet(ModelViewSet):
    serializer_class = ClientModelSerializer
    http_allow_methods = ['PATCH']
    permission_classes = (AllowAny,)
    queryset = User.objects.all()


class SendEmailConfirmationViewSet(ViewSet):
    permission_classes = [AllowAny, ]

    def list(self, request):
        try:
            user = User.objects.get(id=request.query_params["user_id"])

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
            return Response({'status': status.HTTP_200_OK}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"code": e.args[0]}, status.HTTP_500_INTERNAL_SERVER_ERROR)


class EmailConfirmationViewSet(ViewSet):
    permission_classes = [AllowAny, ]

    def list(self, request):
        try:
            try:
                uid = force_text(urlsafe_base64_decode(request.query_params["uid"]))
                query_set = User.objects.all()
                user = get_object_or_404(query_set, pk=uid)

                if user.is_email_verify:
                    return Response({'error': 'Your Email is already verified'}, status=status.HTTP_400_BAD_REQUEST)

                if user is not None:
                    user.is_email_verify = True
                    user.is_active = True
                    user.save()
                    email_address_obj = EmailAddress.objects.get(user=user.id)
                    email_address_obj.verified = True
                    email_address_obj.save()
                    token, created = Token.objects.get_or_create(user=user)
                    is_profile_complete, agent_status = get_agent_status(user.id)
                    return Response({
                        'token': token.key,
                        'user': {
                            'id': user.pk,
                            'email': user.email,
                            'is_active': user.is_active,
                            'is_email_verify': user.is_email_verify,
                            'is_phone_verify': user.is_phone_number_verify,
                            'agent_type': user.agent_type,
                            'is_agent': user.is_agent,
                            'is_profile_complete': is_profile_complete,
                            'agent_status': agent_status,
                            'is_superuser': user.is_superuser
                        }
                    }, status=status.HTTP_200_OK)

                else:
                    return Response({"code": status.HTTP_404_NOT_FOUND}, status.HTTP_404_NOT_FOUND)
            except User.DoesNotExist as e:
                return Response({"code": e.args[0]}, status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({"code": e.args[0]}, status.HTTP_500_INTERNAL_SERVER_ERROR)


class LoginViewSet(ViewSet):
    """Based on rest_framework.authtoken.views.ObtainAuthToken"""

    permission_classes = [AllowAny, ]
    http_allow_methods = ['POST']

    def create(self, request):
        context = {
            "non_field_errors": [
                _('Unable to log in with provided credentials.')
            ]
        }
        email = request.data.get('email')
        password = request.data.get('password')
        kwargs = {'email': email}
        try:
            user = User.objects.get(**kwargs)
            if not user.is_active:
                return Response({'error': 'User is not activate'}, status=status.HTTP_400_BAD_REQUEST)
            if user.check_password(password):
                is_profile_complete, agent_status = get_agent_status(user.id)
                token, created = Token.objects.get_or_create(user=user)

                return Response({
                    'token': token.key,
                    'user': {
                        'id': user.pk,
                        'email': user.email,
                        'is_active': user.is_active,
                        'is_email_verify': user.is_email_verify,
                        'is_phone_verify': user.is_phone_number_verify,
                        'agent_type': user.agent_type,
                        'is_agent': user.is_agent,
                        'is_profile_complete': is_profile_complete,
                        'agent_status': agent_status,
                        'is_superuser': user.is_superuser
                    }
                }, status=status.HTTP_200_OK)

            else:
                return Response(context, status=status.HTTP_400_BAD_REQUEST)

        except User.DoesNotExist as e:
            return Response(context, status=status.HTTP_400_BAD_REQUEST)


class SocialLoginViewSet(ViewSet):
    permission_classes = [AllowAny, ]
    http_allow_methods = ['POST']

    def create(self, request):
        context = {
            "non_field_errors": [
                _('Unable to log in with provided credentials.')
            ]
        }
        email = request.data.get('email')
        password = request.data.get('password')
        is_agent = request.data.get('is_agent', False)
        kwargs = {'email': email}
        try:
            try:
                User.objects.get(email=email)
            except User.DoesNotExist:
                save_user = User(email=email, is_active=True, is_email_verify=True, is_agent=is_agent,
                                 username=generate_unique_username(email, 'user'),
                                 )
                save_user.set_password(password)
                save_user.save()

            user = User.objects.get(**kwargs)
            if not user.is_active:
                return Response({'error': 'User is not activate'}, status=status.HTTP_400_BAD_REQUEST)
            if user.check_password(password):
                is_profile_complete, agent_status = get_agent_status(user.id)
                token, created = Token.objects.get_or_create(user=user)

                return Response({
                    'token': token.key,
                    'user': {
                        'id': user.pk,
                        'email': user.email,
                        'is_active': user.is_active,
                        'is_email_verify': user.is_email_verify,
                        'is_phone_verify': user.is_phone_number_verify,
                        'agent_type': user.agent_type,
                        'is_agent': user.is_agent,
                        'is_profile_complete': is_profile_complete,
                        'agent_status': agent_status,
                        'is_superuser': user.is_superuser
                    }
                }, status=status.HTTP_200_OK)

            else:
                return Response(context, status=status.HTTP_400_BAD_REQUEST)

        except User.DoesNotExist as e:
            return Response(context, status=status.HTTP_400_BAD_REQUEST)


class PhoneNumberViewSet(ViewSet):
    serializer_class = VerifyPhoneNumberSerializer
    permission_classes = [AllowAny]

    def create(self, request):
        try:
            user = User.objects.get(id=request.data.get('user_id'))
            user.phone_number = request.data.get('phone_number')
            user.save()
            Authy.phones.verification_start(user.phone_number, '+92', via='sms')
            return Response({'message': 'Verify your phone Number'}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response(e.args[0], status=status.HTTP_400_BAD_REQUEST)

    @action(detail=False, methods=['POST'])
    def verify_phone_number(self, request):
        query_set = User.objects.all()
        user = get_object_or_404(query_set, pk=int(request.data.get("user_id")))
        serializer = VerifyPhoneNumberSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        verification = Authy.phones.verification_check(user.phone_number, '+92',
                                                       serializer.validated_data['verification_code'])
        if verification.response.ok:
            user.is_phone_number_verify = True
            user.is_active = True
            user.save()
            token, created = Token.objects.get_or_create(user=user)
            is_profile_complete, agent_status = get_agent_status(user.id)
            return Response({
                'token': token.key,
                'user': {
                    'id': user.pk,
                    'email': user.email,
                    'is_agent': user.is_agent,
                    'is_profile_complete': is_profile_complete,
                    'agent_status': agent_status,
                    'is_superuser': user.is_superuser,
                    'is_active': user.is_active,
                    'is_email_verify': user.is_email_verify,
                    'is_phone_verify': user.is_phone_number_verify,
                    'agent_type': user.agent_type,
                }
            }, status=status.HTTP_200_OK)
        else:
            return Response({'code': status.HTTP_400_BAD_REQUEST}, status.HTTP_400_BAD_REQUEST)


class AgentPersonalInformationModelViewSet(ModelViewSet):
    serializer_class = AgentPersonalInformationModelSerializer
    permission_classes = [AllowAny, ]
    queryset = UserPersonalInformation.objects.all()

    def list(self, request, *args, **kwargs):
        try:
            profile = UserPersonalInformation.objects.filter(status='active', is_profile_complete=True)
            return Response(AgentPersonalInformationModelSerializer(profile, many=True).data, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": e.args[0]}, status=status.HTTP_400_BAD_REQUEST)

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        user = serializer.validated_data['user']
        user.agent_type = request.data.get('agent_role')
        user.save()
        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)


class GetAllAgentPersonalInformationModelViewSet(ModelViewSet):
    authentication_classes = [TokenAuthentication, ]
    permission_classes = [AdminPermission, ]
    serializer_class = AgentPersonalInformationModelSerializer
    queryset = UserPersonalInformation.objects.all()


class ChangeEmailPhoneNumberViewSet(ModelViewSet):
    serializer_class = ChangeEmailModelSerializer
    authentication_classes = [TokenAuthentication, ]
    permission_classes = [AllAgentPermission, ]

    def update(self, request, *args, **kwargs):
        user = User.objects.get(id=self.kwargs['pk'])
        if user.email != request.data.get("email") and user.phone_number not in [None,
                                                                                 request.data.get("phone_number")]:
            if user == request.user:
                user.email = request.data.get("email")
                user.phone_number = request.data.get("phone_number")
                # user.is_email_verify = False
                # user.is_verified = False
                user.save()
                # token_generator = PasswordResetTokenGenerator()
                # temp_key = token_generator.make_token(user)
                # url = "{url}/confirm-email/{uid}/{temp_key}".format(
                #     url=settings.FRONTEND_HOST, temp_key=temp_key, uid=urlsafe_base64_encode(force_bytes(user.pk)))
                #
                # from .utils import email_users
                # email_users(user, '[EOZ] Confirm your email address', 'account/account_activation_email.txt', url)

                return Response({"success": "Your Phone Number and Email has updated"})
            else:
                return Response({'error': "User did not match"}, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({'error': "Old email or phone_number "}, status=status.HTTP_400_BAD_REQUEST)


class ResetPasswordViewSet(ViewSet):
    permission_classes = [AllowAny]

    def create(self, request, *args, **kwargs):
        try:
            user = User.objects.get(email=request.data['email'])
            token_generator = PasswordResetTokenGenerator()
            temp_key = token_generator.make_token(user)
            url = "{url}/create-new-password/{uid}/{temp_key}".format(
                url=settings.FRONTEND_HOST, uid=urlsafe_base64_encode(force_bytes(user.pk)), temp_key=temp_key)

            email_users(user, '[EOZ] Create new password',
                        'account/account_reset_password_email.txt', url)
            return Response({"success": "Password reset e-mail has been sent."}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": e.args[0]}, status=status.HTTP_400_BAD_REQUEST)


class AdminPanelModelViewSet(ModelViewSet):
    authentication_classes = [TokenAuthentication, ]
    permission_classes = [AdminPermission, ]
    serializer_class = AgentStatusSerializer
    queryset = UserPersonalInformation.objects.all()

    @action(detail=False, methods=['POST'])
    def agent_status(self, request):
        try:
            serializer = AgentStatusSerializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            user_personal_info = UserPersonalInformation.objects.get(id=serializer.validated_data['agent_id'])
            user_personal_info.status = serializer.validated_data['status']
            user_personal_info.save()
            return Response({'status': status.HTTP_200_OK}, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({'error': e.args[0]}, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=False, methods=['POST'])
    def user_status(self, request):
        try:
            user = User.objects.get(id=request.data['user_id'])
            user.is_active = request.data['is_reactivate']
            user.save()
            return Response({'status': status.HTTP_200_OK}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'error': e.args[0]}, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=False, methods=['GET'])
    def get_all_users(self, request):
        try:
            user = User.objects.filter(is_agent=False)
            serializer = UserModelSerializer(user, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'error': e.args[0]}, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=False, methods=['GET'])
    def get_all_orders(self, request):
        try:
            order = Order.objects.all()
            serializer = OrderModelSerializer(order, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'error': e.args[0]}, status=status.HTTP_400_BAD_REQUEST)


class AgentServicesModelViewSet(ModelViewSet):
    authentication_classes = [TokenAuthentication, ]
    permission_classes = [AllAgentPermission, ]
    serializer_class = AgentServiceModelSerializer
    queryset = AgentServices.objects.all()

    def get_queryset(self):
        return AgentServices.objects.filter(user=self.request.user)


class FilterAgentServices(ModelViewSet):
    permission_classes = [AllowAny, ]
    serializer_class = FilterAgentServiceModelSerializer
    queryset = AgentServices.objects.all()

    def get_queryset(self):
        agent_services = AgentServices.objects.all()
        if self.request.query_params.get('category', False):
            agent_services = agent_services.filter(category=self.request.query_params.get('category'))

        if self.request.query_params.get('sub_category', False):
            agent_services = agent_services.filter(sub_category=self.request.query_params.get('sub_category'))

        if self.request.query_params.get('price', False):
            agent_services = agent_services.filter(price__lte=self.request.query_params.get('price'))

        if self.request.query_params.get('agent_language', False):
            user_ids = UserPersonalInformation.objects.filter(
                languages__icontains=self.request.query_params.get('agent_language')).values_list('user')
            agent_services = agent_services.filter(user__in=user_ids)

        return agent_services

    def retrieve(self, request, *args, **kwargs):
        try:
            service = AgentServices.objects.get(id=kwargs['pk'])
            reviews = ClientServiceReview.objects.filter(service=service)
            rate = ClientServiceReview.objects.filter(service=service).values('rate')
            context = {

                'service': FilterAgentServiceModelSerializer(service, context={"request": request}).data,
                'client_reviews': ClientServiceReviewModelSerializer(reviews, many=True).data,
                "average_rate": round(sum([x['rate'] for x in rate]) / len(rate), 1) if len(rate) != 0 else 0,
                "total_review": len([x['rate'] for x in rate]),
            }

            return Response(context, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'error': e.args[0]}, status=status.HTTP_400_BAD_REQUEST)


class GetAllUserChatModelViewSet(ModelViewSet):
    authentication_classes = [TokenAuthentication, ]
    # permission_classes = [ClientPermission, AllAgentPermission]
    serializer_class = ChatRoomModelSerializer
    queryset = ChatRoom.objects.all()

    def get_queryset(self):
        chat_room = ChatRoom.objects.all()
        chat_room = chat_room.filter(Q(is_receiver=self.request.user) | Q(is_sender=self.request.user))

        if self.request.query_params.get('archive', False):
            pass
            group_name = [x['group__group'] for x in ChatFilter.objects.filter(type=self.request.query_params.get('archive')).values("group__group")]
            chat_room = chat_room.filter(group__group__in=group_name)

        elif self.request.query_params.get('starred', False):
            pass
            group_name = [x['group__group'] for x in ChatFilter.objects.filter(type=self.request.query_params.get('starred')).values("group__group")]
            chat_room = chat_room.filter(group__group__in=group_name)

        return chat_room

    @action(detail=False, methods=['POST'])
    def change_type(self, request):
        try:
            try:
                chat_filter = ChatFilter.objects.get(group__group=request.data['group_name'])
                chat_filter.type = request.data['type']
            except ChatFilter.DoesNotExist as e:
                group = ChatGroup.objects.get(group=request.data['group_name'])
                chat_filter = ChatFilter(group=group,
                                         type=request.data['type'])

            chat_filter.save()

            return Response({'status': status.HTTP_200_OK}, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({'error': e.args[0]}, status=status.HTTP_400_BAD_REQUEST)


class OrderModelViewSet(ModelViewSet):
    authentication_classes = [TokenAuthentication, ]
    serializer_class = OrderModelSerializer
    queryset = Order.objects.all()


class ClientStripePaymentViewSet(ViewSet):
    authentication_classes = [TokenAuthentication, ]
    permission_classes = [ClientPermission, ]

    def create(self, request):
        try:
            serializer = ClientStripeSerializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            pay = stripe.Charge.create(
                amount=serializer.validated_data['amount'] * 100,
                currency="usd",
                description="service payment",
                source=serializer.validated_data['card_token'],  # obtained with Stripe.js
                idempotency_key=str(uuid.uuid1()).replace('-', '_')
            )
            payment = StripePayment(amount=serializer.validated_data['amount'],
                                    payment_token=pay.stripe_id,
                                    client=request.user,
                                    agent_id=serializer.validated_data['agent'],
                                    service_id=serializer.validated_data['service']
                                    )
            payment.save()

            try:
                agent_balance = AgentBalance.objects.get(agent=payment.agent)
                agent_balance.pending_amount = agent_balance.pending_amount + payment.amount
                agent_balance.save()

            except AgentBalance.DoesNotExist:
                agent_balance = AgentBalance(agent=payment.agent, pending_amount=payment.amount)
                agent_balance.save()

            context = {
                'status': status.HTTP_200_OK,
                'stripe_id': payment.id
            }
            return Response(context, status.HTTP_200_OK)
        except Exception as e:
            return Response({'error': e.args[0]}, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=False, methods=['GET'])
    def refund(self, request):
        stripe_amount = StripePayment.objects.get(id=request.query_params['stripe_id'])
        agent_balance = AgentBalance.objects.get(agent=stripe_amount.agent)

        try:
            stripe.Refund.create(
                charge=stripe_amount.payment_token,
            )
            agent_balance.pending_amount = agent_balance.pending_amount - stripe_amount.amount
            stripe_amount.status = 2
            stripe_amount.save()
            agent_balance.save()
            return Response({'status': status.HTTP_200_OK}, status.HTTP_200_OK)

        except Exception as e:
            return Response({'error': e.args[0]}, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=False, methods=['GET'])
    def approve(self, request):
        stripe_amount = StripePayment.objects.get(id=request.query_params['stripe_id'])
        agent_balance = AgentBalance.objects.get(agent=stripe_amount.agent)

        try:
            agent_balance.pending_amount = agent_balance.pending_amount - stripe_amount.amount
            agent_balance.available_amount = agent_balance.available_amount + stripe_amount.amount
            stripe_amount.status = 1
            stripe_amount.save()
            agent_balance.save()
            return Response({'status': status.HTTP_200_OK}, status.HTTP_200_OK)

        except Exception as e:
            return Response({'error': e.args[0]}, status=status.HTTP_400_BAD_REQUEST)


class AgentBalanceModelViewSet(ModelViewSet):
    authentication_classes = [TokenAuthentication]
    permission_classes = [AllAgentPermission]
    queryset = AgentBalance.objects.all()
    serializer_class = AgentBalanceModelSerializer

    def get_object(self):
        return AgentBalance.objects.get(agent_id=self.kwargs['pk'])


class UserInformationViewSet(ModelViewSet):
    authentication_classes = [TokenAuthentication]

    def list(self, request, *args, **kwargs):
        try:
            agent_Information = UserPersonalInformation.objects.get(user=request.user)
            user = agent_Information.user
            context = {
                'agent': {
                    'id': user.pk,
                    'email': user.email,
                    'is_active': user.is_active,
                    'phone_number': user.phone_number,
                    'is_email_verify': user.is_email_verify,
                    'is_phone_verify': user.is_phone_number_verify,
                    'agent_type': user.agent_type,
                    'is_agent': user.is_agent,
                    'is_superuser': user.is_superuser,
                    'profile': AgentPersonalInformationModelSerializer(agent_Information).data
                },
            }

        except UserPersonalInformation.DoesNotExist as e:
            user = request.user
            context = {
                'user': {
                    'id': user.pk,
                    'email': user.email,
                    'phone_number': user.phone_number,
                    'is_active': user.is_active,
                    'is_email_verify': user.is_email_verify,
                    'is_phone_verify': user.is_phone_number_verify,
                    'agent_type': user.agent_type,
                    'is_agent': user.is_agent,
                    'is_superuser': user.is_superuser,
                    'first_name': user.first_name,
                    'last_name': user.last_name

                },
            }

        token = Token.objects.get(user_id=user.id)

        context['token'] = token.key

        return Response(context, status=status.HTTP_200_OK)


class FilterAgentModelViewSet(ModelViewSet):
    permission_classes = [AllowAny, ]
    serializer_class = AgentPersonalInformationModelSerializer
    queryset = UserPersonalInformation.objects.all()

    def retrieve(self, request, *args, **kwargs):
        try:
            agent_info = UserPersonalInformation.objects.filter(status='active', is_profile_complete=True)
            if self.kwargs.get('pk', False):
                agent_info = agent_info.filter(user__agent_type=self.kwargs.get('pk'))

            if request.query_params.get('location', False):
                agent_info = agent_info.filter(city=request.query_params.get('city'))

            if request.query_params.get('language', False):
                agent_info = agent_info.filter(languages__contains=request.query_params.get('language'))

            if request.query_params.get('sub_category', False):
                tmp_arr = []
                for agent in agent_info:
                    if AgentServices.objects.filter(user=agent.user,
                                                    sub_category=request.query_params.get('sub_category')).exists():
                        tmp_arr.append(AgentPersonalInformationModelSerializer(agent).data)

                return Response(tmp_arr, status=status.HTTP_200_OK)

            return Response(AgentPersonalInformationModelSerializer(agent_info, many=True).data,
                            status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'error': e.args[0]}, status=status.HTTP_400_BAD_REQUEST)


class LogoutViewSet(ViewSet):

    def list(self, request):
        user = request.user
        user.updated_at = datetime.datetime.now()
        user.save()
        request.user.auth_token.delete()
        return Response(status=status.HTTP_200_OK)


class PasswordChangeModelViewSet(ModelViewSet):
    authentication_classes = [TokenAuthentication, ]

    def create(self, request, *args, **kwargs):
        try:
            user = request.user
            if user.check_password(request.data.get('old_password', '')):
                user.set_password(request.data.get('new_password', ''))
                user.save()

                return Response({"detail": 'New password has been saved.'}, status=status.HTTP_200_OK)

            return Response({'error': 'Password does not match'}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({'error': e.args[0]}, status=status.HTTP_400_BAD_REQUEST)


class ClientServiceReviewModelViewSet(ModelViewSet):
    authentication_classes = [TokenAuthentication, ]
    serializer_class = ClientServiceReviewModelSerializer
    queryset = ClientServiceReview.objects.all()


