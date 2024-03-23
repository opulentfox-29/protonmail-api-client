"""Exceptions"""


class SendMessageError(Exception):
    """Error when try to send message"""


class InvalidTwoFactorCode(Exception):
    """Invalid Two-Factor Authentication(2FA) code"""
