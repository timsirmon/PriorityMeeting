# utils/email.py
from flask_mail import Message, Mail
from flask import current_app, render_template
from threading import Thread

# Initialize Mail
mail = Mail()

def send_async_email(app, msg):
    with app.app_context():
        mail.send(msg)

def send_email(subject, recipients, text_body, html_body):
    msg = Message(subject, 
                 sender=current_app.config['MAIL_DEFAULT_SENDER'],
                 recipients=recipients)
    msg.body = text_body
    msg.html = html_body
    Thread(target=send_async_email,
           args=(current_app._get_current_object(), msg)).start()

def send_password_reset_email(user):
    token = user.get_reset_token()
    send_email('Reset Your Password',
               recipients=[user.email],
               text_body=render_template('email/reset_password.txt',
                                       user=user, token=token),
               html_body=render_template('email/reset_password.html',
                                       user=user, token=token))

def send_email_confirmation(user):
    token = user.get_email_confirm_token()
    send_email('Confirm Your Email',
               recipients=[user.email],
               text_body=render_template('email/confirm_email.txt',
                                       user=user, token=token),
               html_body=render_template('email/confirm_email.html',
                                       user=user, token=token))