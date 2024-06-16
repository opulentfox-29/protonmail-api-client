"""Exceptions"""


class SendMessageError(Exception):
    """Error when try to send message"""


class InvalidTwoFactorCode(Exception):
    """Invalid Two-Factor Authentication(2FA) code"""


class NoKeysForDecryptThisMessage(Exception):
    """
    No keys for decrypt this message,
    maybe you created new key then re-login,
    if you deleted key then you can't decrypt this message
    """


class LoadSessionError(Exception):
    """Error while load session, maybe this session file was created in other version? then re-login"""
