from django.urls import path, include
from rest_framework.routers import DefaultRouter
from home.api.v1.viewsets import (
    SignUpModelViewSet, LoginViewSet, PhoneNumberViewSet,
    AgentPersonalInformationModelViewSet, AdminPanelModelViewSet, AgentServicesModelViewSet, FilterAgentServices,
    ClientSignUpModelViewSet, EmailConfirmationViewSet, SendEmailConfirmationViewSet, GetAllUserChatModelViewSet,
    ResetPasswordViewSet, ChangeEmailPhoneNumberViewSet, OrderModelViewSet, ClientStripePaymentViewSet,
    AgentBalanceModelViewSet, UserInformationViewSet, GetAllAgentPersonalInformationModelViewSet, SocialLoginViewSet,
    FilterAgentModelViewSet, LogoutViewSet, PasswordChangeModelViewSet, ClientServiceReviewModelViewSet,

)

router = DefaultRouter()

router.register('signup', SignUpModelViewSet, basename='signup')
router.register('complete_client_signup', ClientSignUpModelViewSet, basename='client-signup')
router.register("send_confirmation_email", SendEmailConfirmationViewSet, basename="send_confirmation_email")
router.register("email/confirm", EmailConfirmationViewSet, basename="email-confirmation")
router.register("reset/password", ResetPasswordViewSet, basename="reset-password")
router.register("password/change", PasswordChangeModelViewSet, basename="change-password")

router.register('login', LoginViewSet, basename='login')
router.register('social_login', SocialLoginViewSet, basename='social-login')
router.register('user_info', UserInformationViewSet, basename='user-info')
router.register("change_email_phone_number", ChangeEmailPhoneNumberViewSet, basename="change-email")
router.register("phone_number", PhoneNumberViewSet, basename="phone-number")
router.register("agent_personal_information", AgentPersonalInformationModelViewSet,
                basename="agent-personal-information")
router.register('admin_get_all_agents', GetAllAgentPersonalInformationModelViewSet, basename='admin-get-all-agents')
router.register('agent_create_services', AgentServicesModelViewSet, basename="agent-create-services")
router.register('admin_panel', AdminPanelModelViewSet, basename='agent-status')
router.register('filter_courses', FilterAgentServices, basename='filter-courses')
router.register('chats', GetAllUserChatModelViewSet, basename='chats')
router.register('orders', OrderModelViewSet, basename='orders')
router.register('stripe', ClientStripePaymentViewSet, basename='stripe')
router.register('agent_balance', AgentBalanceModelViewSet, basename='agent-balance')
router.register('filter_agent', FilterAgentModelViewSet, basename='filter-agent')
router.register('logout', LogoutViewSet, basename='logout')
router.register('service_review', ClientServiceReviewModelViewSet, basename='service-review')
urlpatterns = [
    path('', include(router.urls)),
]
