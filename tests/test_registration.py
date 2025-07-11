import unittest
from unittest.mock import patch, MagicMock
import base64

from src.protonmail.client import ProtonMail
from src.protonmail.exceptions import UsernameUnavailableError, VerificationError, RegistrationError, InvalidCaptcha
from src.protonmail.models import CaptchaConfig, UserMail, TokenType, UserType
from src.protonmail.constants import SRP_VERSION, SRP_MODULUS_KEY

# Helper to create a mock response object
def mock_response(status_code, json_data=None, text_data=None, content_data=None):
    mock_resp = MagicMock()
    mock_resp.status_code = status_code
    if json_data is not None:
        mock_resp.json = MagicMock(return_value=json_data)
    if text_data is not None:
        mock_resp.text = text_data
    if content_data is not None:
        mock_resp.content = content_data
    return mock_resp

# Sample PGP encrypted armored modulus (replace with a realistic one if possible for more accurate testing)
# For now, just a base64 encoded string that PGP().message can handle
MOCK_ARMORED_MODULUS = """-----BEGIN PGP MESSAGE-----
Version: OpenPGP.js v4.10.10
Comment: https://openpgpjs.org

wyYEIBADAQALAJb8xwUVScEbFiEE78p8J8yZ0X0XoGfL1234567890ABCDEF
S8vT42e7Q8vT42e7Q8vT42e7Q8vT42e7Q8vT42e7Q8vT42e7Q8vT42e7Q8vT
42e7Q8vT42e7Q8vT42e7Q8vT42e7Q8vT42e7Q8vT42e7Q8vT42e7Q8vT42e7
Q8vT42e7Q8vT42e7Q8vT42e7Q8vT42e7Q8vT42e7Q8vT42e7Q8vT42e7Q8vT
42e7Q8vT42e7Q8vT42e7Q8vT42e7Q8vT42e7Q8vT42e7Q8vT42e7Q8vT42e7
=abcd
-----END PGP MESSAGE-----"""
MOCK_DECODED_MODULUS_BYTES = b"mock_modulus_bytes_for_srp_testing_123"


class TestRegistration(unittest.TestCase):

    def setUp(self):
        self.client = ProtonMail(logging_level=4) # Disable logging for tests
        # Mock PGP decryption for modulus
        self.pgp_patcher = patch.object(self.client.pgp, 'message')
        self.mock_pgp_message = self.pgp_patcher.start()

        # Configure the mock to return a MagicMock that has a 'message' attribute
        mock_inner_pgp_message = MagicMock()
        mock_inner_pgp_message.message = base64.b64encode(MOCK_DECODED_MODULUS_BYTES) # base64 encode the mock bytes
        self.mock_pgp_message.return_value = mock_inner_pgp_message


    def tearDown(self):
        self.pgp_patcher.stop()

    @patch.object(ProtonMail, '_get')
    def test_get_username_available_success(self, mock_get):
        mock_get.return_value = mock_response(200, {'Code': 1000})
        self.assertTrue(self.client.get_username_available("newuser"))
        mock_get.assert_called_once_with('account', 'core/v4/users/available', params={'Name': 'newuser'})

    @patch.object(ProtonMail, '_get')
    def test_get_username_available_failure_code(self, mock_get):
        mock_get.return_value = mock_response(200, {'Code': 12102, 'Error': 'Username taken'})
        self.assertFalse(self.client.get_username_available("existinguser"))

    @patch.object(ProtonMail, '_get')
    def test_get_username_available_failure_status(self, mock_get):
        mock_get.return_value = mock_response(400, {'Error': 'Bad request'})
        self.assertFalse(self.client.get_username_available("anyuser"))

    @patch.object(ProtonMail, '_post')
    def test_send_verification_code_success(self, mock_post):
        mock_post.return_value = mock_response(200, {'Code': 1000})
        self.client.send_verification_code("newuser", "test@example.com")
        expected_payload = {
            'Username': 'newuser',
            'Type': TokenType.EMAIL.value,
            'Destination': {'Address': 'test@example.com'}
        }
        mock_post.assert_called_once_with('account', 'core/v4/users/code', json=expected_payload)

    @patch.object(ProtonMail, '_post')
    def test_send_verification_code_username_unavailable(self, mock_post):
        mock_post.return_value = mock_response(200, {'Code': 12102, 'Error': 'Username already exists'})
        with self.assertRaises(UsernameUnavailableError):
            self.client.send_verification_code("existinguser", "test@example.com")

    @patch.object(ProtonMail, '_post')
    def test_send_verification_code_failure_other(self, mock_post):
        mock_post.return_value = mock_response(200, {'Code': 5001, 'Error': 'Generic error'})
        with self.assertRaises(VerificationError):
            self.client.send_verification_code("newuser", "test@example.com")

    @patch.object(ProtonMail, '_get') # For _get_modulus
    @patch.object(ProtonMail, '_post') # For create_user itself
    @patch('src.protonmail.client.SRPUser') # To mock SRPUser instantiation and methods
    def test_create_user_success(self, mock_srp_user_class, mock_post, mock_get_modulus):
        # Mock _get_modulus response
        mock_get_modulus.return_value = mock_response(200, {
            SRP_MODULUS_KEY: MOCK_ARMORED_MODULUS,
            'ModulusID': 'test_modulus_id',
            'Version': SRP_VERSION
        })

        # Mock SRPUser instance and its methods
        mock_srp_instance = MagicMock()
        mock_srp_instance.get_srp_verifier_params.return_value = {
            "Version": SRP_VERSION,
            "ModulusID": "test_modulus_id",
            "Salt": "test_salt_base64_encoded_string",
            "Verifier": "test_verifier_hex_encoded_string"
        }
        mock_srp_user_class.return_value = mock_srp_instance

        # Mock create user _post response
        mock_post.return_value = mock_response(200, {
            'Code': 1000,
            'User': {'ID': 'user123', 'Name': 'newuser', 'Addresses': [{'Email': 'newuser@proton.me'}]}
        })

        user = self.client.create_user("newuser", "password123", "verify@example.com", "123456")
        self.assertIsInstance(user, UserMail)
        self.assertEqual(user.name, "newuser")
        self.assertEqual(user.address, "newuser@proton.me")

        mock_get_modulus.assert_called_once_with('account', 'core/v4/auth/modulus')
        mock_srp_user_class.assert_called_once_with("password123", MOCK_DECODED_MODULUS_BYTES, srp_version=SRP_VERSION)
        mock_srp_instance.get_srp_verifier_params.assert_called_once_with(modulus_id='test_modulus_id')

        expected_create_payload = {
            'Type': UserType.MAIL.value,
            'Username': 'newuser',
            'Domain': 'proton.me',
            'Auth': {
                'Version': SRP_VERSION,
                'ModulusID': 'test_modulus_id',
                'Salt': 'test_salt_base64_encoded_string',
                'Verifier': 'test_verifier_hex_encoded_string'
            },
            'Token': '123456',
            'TokenType': TokenType.EMAIL.value
        }
        mock_post.assert_called_once_with('account', 'core/v4/users', json=expected_create_payload)


    @patch.object(ProtonMail, '_get') # For _get_modulus and CAPTCHA js
    @patch.object(ProtonMail, '_post') # For create_user and CAPTCHA validate
    @patch('src.protonmail.client.SRPUser')
    @patch('src.protonmail.client.get_captcha_puzzle_coordinates') # For auto CAPTCHA
    @patch('src.protonmail.client.solve_challenge') # For auto CAPTCHA
    def test_create_user_with_captcha_auto_success(
        self, mock_solve_challenge, mock_get_puzzle, mock_srp_user_class, mock_post, mock_get_modulus_and_captcha_js
    ):
        # --- Initial setup for modulus and SRP (same as non-CAPTCHA success) ---
        mock_get_modulus_and_captcha_js.side_effect = [
            mock_response(200, { # First call: _get_modulus
                SRP_MODULUS_KEY: MOCK_ARMORED_MODULUS,
                'ModulusID': 'test_modulus_id',
                'Version': SRP_VERSION
            }),
            mock_response(200, text_data="function sendToken(a){return sendToken('subtoken_part');}"), # Second call: CAPTCHA JS
            mock_response(200, json_data={ # Third call: CAPTCHA init
                'token': 'captcha_init_token',
                'contestId': 'contest123',
                'challenges': ['challenge1', 'challenge2']
            }),
            mock_response(200, content_data=b"image_bytes"), # Fourth call: CAPTCHA bg image
            mock_response(200) # Fifth call: CAPTCHA validate
        ]

        mock_srp_instance = MagicMock()
        mock_srp_instance.get_srp_verifier_params.return_value = {
            "Version": SRP_VERSION, "ModulusID": "test_modulus_id",
            "Salt": "test_salt", "Verifier": "test_verifier"
        }
        mock_srp_user_class.return_value = mock_srp_instance

        mock_get_puzzle.return_value = (10, 20) # Mock puzzle coordinates
        mock_solve_challenge.side_effect = ['answer1', 'answer2'] # Mock challenge answers

        # --- Mock create user _post responses: first fails with CAPTCHA, second succeeds ---
        mock_post.side_effect = [
            mock_response(200, { # First call to create_user: CAPTCHA required
                'Code': 9001,
                'Error': 'CAPTCHA required',
                'Details': {'HumanVerificationToken': 'captcha_token_from_api'}
            }),
            mock_response(200, { # Second call to create_user: Success
                'Code': 1000,
                'User': {'ID': 'user123', 'Name': 'newuser', 'Addresses': [{'Email': 'newuser@proton.me'}]}
            })
        ]

        user = self.client.create_user("newuser", "password123", "verify@example.com", "123456", captcha_config=CaptchaConfig(type=CaptchaConfig.CaptchaType.AUTO))
        self.assertIsInstance(user, UserMail)
        self.assertEqual(user.name, "newuser")

        self.assertEqual(mock_post.call_count, 2)
        # Further assertions can be made on the headers of the second call to _post to ensure CAPTCHA tokens were included


    @patch.object(ProtonMail, '_get')
    @patch.object(ProtonMail, '_post')
    @patch('src.protonmail.client.SRPUser')
    def test_create_user_failure_username_unavailable(self, mock_srp_user_class, mock_post, mock_get_modulus):
        mock_get_modulus.return_value = mock_response(200, {SRP_MODULUS_KEY: MOCK_ARMORED_MODULUS, 'ModulusID': 'id1', 'Version': SRP_VERSION})
        mock_srp_instance = MagicMock()
        mock_srp_instance.get_srp_verifier_params.return_value = {"Version": SRP_VERSION, "ModulusID": "id1", "Salt": "s", "Verifier": "v"}
        mock_srp_user_class.return_value = mock_srp_instance
        mock_post.return_value = mock_response(200, {'Code': 12102, 'Error': 'Username already taken'})

        with self.assertRaises(UsernameUnavailableError):
            self.client.create_user("existinguser", "password123", "verify@example.com", "123456")

    @patch.object(ProtonMail, '_get')
    @patch.object(ProtonMail, '_post')
    @patch('src.protonmail.client.SRPUser')
    def test_create_user_failure_invalid_token(self, mock_srp_user_class, mock_post, mock_get_modulus):
        mock_get_modulus.return_value = mock_response(200, {SRP_MODULUS_KEY: MOCK_ARMORED_MODULUS, 'ModulusID': 'id1', 'Version': SRP_VERSION})
        mock_srp_instance = MagicMock()
        mock_srp_instance.get_srp_verifier_params.return_value = {"Version": SRP_VERSION, "ModulusID": "id1", "Salt": "s", "Verifier": "v"}
        mock_srp_user_class.return_value = mock_srp_instance
        mock_post.return_value = mock_response(200, {'Code': 12106, 'Error': 'Invalid verification token'})

        with self.assertRaises(VerificationError):
            self.client.create_user("newuser", "password123", "verify@example.com", "wrongcode")

    @patch.object(ProtonMail, '_get') # For _get_modulus and CAPTCHA js
    @patch.object(ProtonMail, '_post') # For create_user and CAPTCHA validate
    @patch('src.protonmail.client.SRPUser')
    def test_create_user_with_captcha_failure_invalid_captcha(
        self, mock_srp_user_class, mock_post, mock_get_modulus_and_captcha_js
    ):
        # --- Initial setup for modulus and SRP ---
        mock_get_modulus_and_captcha_js.side_effect = [
            mock_response(200, { # First call: _get_modulus
                SRP_MODULUS_KEY: MOCK_ARMORED_MODULUS,
                'ModulusID': 'test_modulus_id',
                'Version': SRP_VERSION
            }),
             # Subsequent calls for CAPTCHA processing if needed by _captcha_processing
            mock_response(200, text_data="function sendToken(a){return sendToken('subtoken_part');}"),
            mock_response(200, json_data={'token': 'init_token', 'contestId': 'cid', 'challenges':[]}), # captcha init
            mock_response(200, content_data=b"image_data"), # captcha bg
            mock_response(400, json_data={'Error': 'Invalid CAPTCHA solution'}) # captcha validate fails
        ]

        mock_srp_instance = MagicMock()
        mock_srp_instance.get_srp_verifier_params.return_value = {
            "Version": SRP_VERSION, "ModulusID": "test_modulus_id",
            "Salt": "test_salt", "Verifier": "test_verifier"
        }
        mock_srp_user_class.return_value = mock_srp_instance

        # --- Mock create user _post response: first fails with CAPTCHA ---
        mock_post.return_value = mock_response(200, {
            'Code': 9001,
            'Error': 'CAPTCHA required',
            'Details': {'HumanVerificationToken': 'captcha_token_from_api'}
        })

        # Patch _captcha_auto_solving to raise InvalidCaptcha
        with patch.object(ProtonMail, '_captcha_auto_solving', side_effect=InvalidCaptcha("Test CAPTCHA fail")):
            with self.assertRaises(InvalidCaptcha):
                self.client.create_user("newuser", "password123", "verify@example.com", "123456", captcha_config=CaptchaConfig(type=CaptchaConfig.CaptchaType.AUTO))


if __name__ == '__main__':
    unittest.main()
