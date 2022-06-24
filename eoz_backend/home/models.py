from django.db import models
from django.contrib.auth import get_user_model

from chats.models import ChatGroup

User = get_user_model()


# Create your models here.


class AgentServices(models.Model):
    title = models.CharField(max_length=256, default='')
    description = models.TextField(default='')
    category = models.CharField(max_length=128, default='')
    sub_category = models.CharField(max_length=128, default='')
    price = models.IntegerField(default=0)
    photo = models.FileField(upload_to='service_mages/', default=0)
    is_show = models.BooleanField(default=True)
    is_price_per_week = models.BooleanField(default=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    created_at = models.DateField(auto_now_add=True)
    updated_at = models.DateField(auto_now=True)

    class Meta:
        ordering = ('-created_at',)

    def __str__(self):
        return self.title


class ClientServiceReview(models.Model):
    rate = models.FloatField()
    review = models.TextField()
    client = models.ForeignKey(User, on_delete=models.CASCADE)
    agent = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True, related_name='agent_review')
    service = models.ForeignKey(AgentServices, on_delete=models.CASCADE)
    created_at = models.DateField(auto_now_add=True)
    updated_at = models.DateField(auto_now=True)


ORDER_STATUS = (
    ('pending', 'pending'),
    ('active', 'active'),
    ('closed', 'closed')
)


class Order(models.Model):
    price = models.IntegerField()
    status = models.CharField(max_length=16, choices=ORDER_STATUS, default='pending')
    is_paid = models.BooleanField(default=False)
    agent = models.ForeignKey(User, on_delete=models.CASCADE, related_name="agent_service_fee")
    client = models.ForeignKey(User, on_delete=models.CASCADE, related_name="client_paid_fee")
    service = models.ForeignKey(AgentServices, on_delete=models.CASCADE)
    created_at = models.DateField(auto_now_add=True)
    updated_at = models.DateField(auto_now=True)


PAYMENT_STATUS = (
    (0, 0),  # open
    (1, 1),  # closed
    (2, 2),  # cancel
)


class StripePayment(models.Model):
    amount = models.IntegerField()
    payment_token = models.CharField(max_length=256)
    service = models.ForeignKey(AgentServices, on_delete=models.CASCADE)
    client = models.ForeignKey(User, on_delete=models.CASCADE, related_name='eoz_client')
    agent = models.ForeignKey(User, on_delete=models.CASCADE, related_name='eoz_agent')
    status = models.IntegerField(choices=PAYMENT_STATUS, default=0)
    created_at = models.DateField(auto_now_add=True)
    updated_at = models.DateField(auto_now=True)


class AgentBalance(models.Model):
    pending_amount = models.FloatField(default=0)
    available_amount = models.FloatField(default=0)
    agent = models.OneToOneField(User, on_delete=models.CASCADE)
    created_at = models.DateField(auto_now_add=True)
    updated_at = models.DateField(auto_now=True)


CHAT_FILTER_TYPES = (
    (1, 1),  # delete
    (2, 2),  # starred
    (3, 3),  # archive
)


class ChatFilter(models.Model):
    type = models.IntegerField(choices=CHAT_FILTER_TYPES)
    group = models.OneToOneField(ChatGroup, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
