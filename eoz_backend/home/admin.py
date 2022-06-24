from django.contrib import admin

# Register your models here.
from home.models import (
    AgentServices, ClientServiceReview, Order,
    StripePayment
)

admin.site.register(AgentServices)
admin.site.register(ClientServiceReview)
admin.site.register(Order)
admin.site.register(StripePayment)
