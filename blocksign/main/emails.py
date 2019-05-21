from django.core.mail import EmailMessage
from django.conf import settings


def validated_email(sign_user):
    subject = "Validación"
    msg_html = render_to_string('emails/suggestionEmail.html', context)
    from_address = settings.SERVER_EMAIL
    to_address = sign_user.user.email
    mailbot_send_mail(subject, msg_html, from_address, to_address)

def mailbot_send_mail(subject, msg_html, from_address, to_address):
        email = EmailMessage(subject, msg_html, from_address, to_address)
        email.content_subtype = "html"
        email.send()
        return True
