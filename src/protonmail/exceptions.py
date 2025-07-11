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


class AddressNotFound(Exception):
    """Email address was not found"""


class CantUploadAttachment(Exception):
    """Error when try to upload attachment"""


class CantGetLabels(Exception):
    """Error when try to get labels"""

class CantSetLabel(Exception):
    """Error when try to set label for a message"""

class CantUnsetLabel(Exception):
    """Error when try to unset label for a message"""


class CantSolveImageCaptcha(Exception):
    """Error when try to solve image CAPTCHA, maybe this image hard, just retry login"""


class InvalidCaptcha(Exception):
    """Error when solved CAPTCHA, but something wrong"""


class ProtonMailException(Exception):
    """Base exception for ProtonMail API client errors."""
    pass


class RegistrationError(ProtonMailException):
    """Raised when account registration fails for a general reason."""
    pass


class UsernameUnavailableError(RegistrationError):
    """Raised when a username is unavailable during registration."""
    pass


class VerificationError(RegistrationError):
    """Raised when verification (e.g., email or SMS code) fails during registration."""
    pass
