"""SMTP Email Notification Module."""
from .smtp_mailer import SMTPMailer, MailerError

__all__ = ["SMTPMailer", "MailerError"]

