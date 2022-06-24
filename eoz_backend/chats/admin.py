from django.contrib import admin
from chats.models import (
    ChatGroup,
    ChatRoom
)
# Register your models here.

admin.site.register(ChatGroup)
admin.site.register(ChatRoom)
