import base64

from django.core.mail import EmailMessage
from django.conf import settings
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from django.template.loader import render_to_string


def validated_email(sign_user, owner):
    subject = "Validación"
    token=default_token_generator.make_token(sign_user.user)
    user_id=urlsafe_base64_encode(force_bytes(sign_user.user.pk)).decode()
    context = {'token':token, 'user_id':user_id, 'owner':owner}
    msg_html = render_to_string('emails/validacion.html', context)
    from_address = settings.SERVER_EMAIL
    to_address = [sign_user.user.email]
    send_mail_address(subject, msg_html, from_address, to_address)

def send_mail_address(subject, msg_html, from_address, to_address):
    email = EmailMessage(subject, msg_html, from_address, to_address)
    email.content_subtype = "html"
    email.send()
    return True
