from django.db import models
from django.contrib.auth import get_user_model

User = get_user_model()


class ChatGroup(models.Model):
    group = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.group


class ChatRoom(models.Model):

    message = models.TextField()
    is_sender = models.ForeignKey(User, on_delete=models.CASCADE, related_name="user_send_message")
    is_receiver = models.ForeignKey(User, on_delete=models.CASCADE, related_name="user_receive_message")
    group = models.ForeignKey(ChatGroup, on_delete=models.CASCADE)
    order = models.TextField(default="{}")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
