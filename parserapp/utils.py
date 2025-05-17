import random
import os
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from django.conf import settings

def generate_otp(length=6):
    return ''.join([str(random.randint(0, 9)) for _ in range(length)])

    
def send_otp_email(to_email, otp):
    message = Mail(
        from_email=settings.SENDGRID_FROM_EMAIL,
        to_emails=to_email,
        subject='Your OTP Code',
        plain_text_content=f'Your OTP code is: {otp}'
    )
    try:
        sg = SendGridAPIClient(settings.SENDGRID_API_KEY)
        response = sg.send(message)
        return response.status_code
    except Exception as e:
        print(f'Error sending email: {e}')
        return None