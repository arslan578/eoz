from channels import Group
import json
# Connected to websocket.connect
from chats.models import (
    ChatGroup, ChatRoom
)
from home.models import Order


def ws_add(message):
    # Accept the connection
    message.reply_channel.send({"accept": True})
    # Add to the chat group
    group = message.content['path'][1:-1]
    try:
        ChatGroup.objects.get(group=group)
    except ChatGroup.DoesNotExist:
        ChatGroup.objects.create(group=group)
    Group(group).add(message.reply_channel)
    # Connected to websocket.receive


def ws_message(message):
    group = message.content['path'][1:-1]
    chat_group = ChatGroup.objects.get(group=group)
    data = json.loads(message.content['text'])
    ChatRoom.objects.create(group=chat_group, message=data['message'],
                            is_sender_id=data['is_sender'], is_receiver_id=data['is_receiver'],
                            order=data.get('create_order', ''))

    if data.get('create_order', False):
        order = Order(price=data['create_order']['price'],
                      agent_id=data['create_order']['agent'],
                      client_id=data['create_order']['client'],
                      service_id=data['create_order']['service'])

        order.save()

    Group(group).send({
        "text": data['message'],
    })


def ws_disconnect(message):
    group = message.content['path'][1:-1]
    Group(group).discard(message.reply_channel)
