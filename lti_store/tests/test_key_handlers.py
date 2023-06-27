from unittest.mock import Mock, patch, call

import ddt
from Cryptodome.PublicKey import RSA
from django.test.testcases import TestCase
from jwkest import BadSignature, BadSyntax, WrongNumberOfParts
from jwkest.jwk import RSAKey
from jwkest.jws import JWS
from jwkest.jwt import JWT

from lti_store import exceptions
from lti_store.key_handlers import PlatformKeyHandler, ToolKeyHandler


TOKEN = "test-token"
KID = "test-kid"
KEYSET = "test-keyset"
KEYSET_URL = "test-keyset-url"
UNPACK = Mock(headers={"kid": KID})
MSG = {"iss": "test-issuer", "aud": "test-aud"}
SIGNED_MSG = "test-signed-message"


@ddt.ddt
class TestPlatformKeyHandler(TestCase):
    """
    Unit tests for PlatformKeyHandler.
    """

    def setUp(self):
        super().setUp()

        self.rsa_key_id = "1"
        self.rsa_key = RSA.generate(2048).export_key("PEM")
        self.key_handler = PlatformKeyHandler(
            key_pem=self.rsa_key, key_id=self.rsa_key_id
        )

    @patch("lti_store.key_handlers.copy.deepcopy", return_value=MSG)
    @patch.object(JWS, "__init__", return_value=None)
    @patch.object(JWS, "sign_compact", return_value=SIGNED_MSG)
    def test_encode_and_sign(self, sign_compact_mock, jws_mock, deepcopy_mock):
        """
        Test if a message was correctly signed with RSA key.
        """
        self.assertEqual(self.key_handler.encode_and_sign(MSG), SIGNED_MSG)
        deepcopy_mock.assert_called_once_with(MSG)
        jws_mock.assert_called_once_with(MSG, alg="RS256", cty="JWT")
        sign_compact_mock.assert_called_once_with([self.key_handler.key])

    @patch("time.time", return_value=1000)
    @patch("lti_store.key_handlers.copy.deepcopy")
    @patch.object(JWS, "__init__", return_value=None)
    @patch.object(JWS, "sign_compact", return_value=SIGNED_MSG)
    def test_encode_and_sign_with_exp(
        self,
        sign_compact_mock,
        jws_mock,
        deepcopy_mock,
        mock_time,
    ):
        """
        Test if a message was correctly signed and has exp and iat parameters.
        """
        message_mock = Mock()
        deepcopy_mock.return_value = message_mock

        self.assertEqual(
            self.key_handler.encode_and_sign(message_mock, expiration=1000),
            SIGNED_MSG,
        )
        deepcopy_mock.assert_called_once_with(message_mock)
        message_mock.update.assert_called_once_with({"iat": 1000, "exp": 2000})
        mock_time.assert_has_calls([call(), call()])
        jws_mock.assert_called_once_with(message_mock, alg="RS256", cty="JWT")
        sign_compact_mock.assert_called_once_with([self.key_handler.key])

    def test_invalid_rsa_key(self):
        """
        Check that class raises when trying to import invalid RSA Key.
        """
        with self.assertRaises(exceptions.InvalidRsaKey):
            PlatformKeyHandler(key_pem="invalid PEM input")

    def test_empty_rsa_key(self):
        """
        Check that class doesn't fail instancing when not using a key.
        """
        empty_key_handler = PlatformKeyHandler(key_pem="")

        # Trying to encode a message should fail
        with self.assertRaises(exceptions.RsaKeyNotSet):
            empty_key_handler.encode_and_sign({})

        # Public JWK should return an empty value
        self.assertEqual(empty_key_handler.get_public_jwk(), {"keys": []})

    @patch("time.time", return_value=1000)
    @patch.object(JWS, "verify_compact")
    def test_validate_and_decode(self, verify_compact_mock, mock_time):
        """
        Test validate and decode with all parameters.
        """
        decoded_message = {**MSG, "iat": 1000, "exp": 2000}
        verify_compact_mock.return_value = decoded_message

        signed_token = self.key_handler.encode_and_sign(MSG, expiration=1000)

        self.assertEqual(
            self.key_handler.validate_and_decode(signed_token),
            decoded_message,
        )
        verify_compact_mock.assert_called_once_with(
            signed_token, keys=[self.key_handler.key]
        )
        mock_time.assert_has_calls([call(), call(), call()])

    @patch("time.time", return_value=1000)
    def test_validate_and_decode_expired(self, mock_time):
        """
        Test validate and decode with all parameters.
        """
        signed_token = self.key_handler.encode_and_sign({}, expiration=-10)

        with self.assertRaises(exceptions.TokenSignatureExpired):
            self.key_handler.validate_and_decode(signed_token)

    def test_validate_and_decode_invalid_iss(self):
        """
        Test validate and decode with invalid iss.
        """
        signed_token = self.key_handler.encode_and_sign({"iss": "wrong"})

        with self.assertRaises(exceptions.InvalidClaimValue):
            self.key_handler.validate_and_decode(signed_token, iss="right")

    def test_validate_and_decode_invalid_aud(self):
        """
        Test validate and decode with invalid aud.
        """
        signed_token = self.key_handler.encode_and_sign({"aud": "wrong"})

        with self.assertRaises(exceptions.InvalidClaimValue):
            self.key_handler.validate_and_decode(signed_token, aud="right")

    def test_validate_and_decode_no_jwt(self):
        """
        Test validate and decode with invalid JWT.
        """
        with self.assertRaises(exceptions.MalformedJwtToken):
            self.key_handler.validate_and_decode("1.2.3")

    def test_validate_and_decode_no_keys(self):
        """
        Test validate and decode when no keys are available.
        """
        signed_token = self.key_handler.encode_and_sign({})
        self.key_handler.key.kid = "invalid_kid"  # Changing the KID so it doesn't match

        with self.assertRaises(exceptions.NoSuitableKeys):
            self.key_handler.validate_and_decode(signed_token)


@ddt.ddt
class TestToolKeyHandler(TestCase):
    """
    Unit tests for ToolKeyHandler.
    """

    def setUp(self):
        super().setUp()

        self.rsa_key_id = "1"

        # Generate RSA and save exports
        rsa_key = RSA.generate(2048)
        self.key = RSAKey(key=rsa_key, kid=self.rsa_key_id)
        self.public_key = rsa_key.publickey().export_key()

        # Key handler
        self.key_handler = None

    def _setup_key_handler(self):
        """
        Set up a instance of the key handler.
        """
        self.key_handler = ToolKeyHandler(public_key=self.public_key)

    def test_import_rsa_key(self):
        """
        Check if the class is correctly instanced using a valid RSA key.
        """
        ToolKeyHandler(public_key=self.public_key)

    def test_import_invalid_rsa_key(self):
        """
        Check if the class errors out when using a invalid RSA key.
        """
        with self.assertRaises(exceptions.InvalidRsaKey):
            ToolKeyHandler(public_key="invalid-key")

    def test_get_empty_keyset(self):
        """
        Test getting an empty keyset.
        """
        self.assertEqual(
            ToolKeyHandler()._get_keyset(),
            [],
        )

    @patch("lti_store.key_handlers.load_jwks_from_url", return_value="k")
    def test_get_keyset_with_keyset_url(self, load_jwks_from_url_mock):
        """
        Check getting a keyset from a keyset URL.
        """
        keyset = ToolKeyHandler(keyset_url=KEYSET_URL)._get_keyset()

        self.assertEqual(len(keyset), 1)
        self.assertEqual(keyset[0], "k")
        load_jwks_from_url_mock.assert_called_once_with(KEYSET_URL)

    @patch("lti_store.key_handlers.load_jwks_from_url", side_effect=Exception)
    def test_get_keyset_with_invalid_keyset_url(self, load_jwks_from_url_mock):
        """
        Check getting a keyset from an invalid keyset URL.
        """
        with self.assertRaises(exceptions.NoSuitableKeys):
            ToolKeyHandler(keyset_url=KEYSET_URL)._get_keyset()

    def test_get_keyset_with_pub_key(self):
        """
        Check getting a keyset from a RSA key.
        """
        self._setup_key_handler()

        keyset = self.key_handler._get_keyset(key_id=self.rsa_key_id)

        self.assertEqual(len(keyset), 1)
        self.assertEqual(keyset[0].kid, self.rsa_key_id)

    @patch("time.time", return_value=1000)
    @patch.object(JWT, "unpack", return_value=UNPACK)
    @patch.object(JWS, "verify_compact")
    @patch.object(ToolKeyHandler, "_get_keyset", return_value=KEYSET)
    def test_validate_and_decode(
        self,
        get_keyset_mock,
        verify_compact_mock,
        unpack_mock,
        mock_time,
    ):
        """
        Check that the validate and decode works.
        """
        message = {"exp": 1200}
        verify_compact_mock.return_value = message
        self._setup_key_handler()

        self.assertEqual(self.key_handler.validate_and_decode(TOKEN), message)
        unpack_mock.assert_called_once_with(TOKEN)
        get_keyset_mock.assert_called_once_with(KID)
        verify_compact_mock.assert_called_once_with(TOKEN, keys=KEYSET)
        mock_time.assert_called_once_with()

    @patch("time.time", return_value=1000)
    @patch.object(JWT, "unpack", return_value=UNPACK)
    @patch.object(JWS, "verify_compact", return_value={"exp": 910})
    @patch.object(ToolKeyHandler, "_get_keyset", return_value=KEYSET)
    def test_validate_and_decode_expired(
        self,
        get_keyset_mock,
        verify_compact_mock,
        unpack_mock,
        mock_time,
    ):
        """
        Check that the validate and decode raises when signature expires.
        """
        self._setup_key_handler()

        with self.assertRaises(exceptions.TokenSignatureExpired):
            self.key_handler.validate_and_decode(TOKEN)

    @patch.object(JWT, "unpack", return_value=UNPACK)
    @patch.object(JWS, "verify_compact", side_effect=exceptions.NoSuitableKeys)
    @patch.object(ToolKeyHandler, "_get_keyset", return_value=KEYSET)
    def test_validate_and_decode_no_keys(
        self,
        get_keyset_mock,
        verify_compact_mock,
        unpack_mock,
    ):
        """
        Check that the validate and decode raises when no keys are found.
        """
        with self.assertRaises(exceptions.NoSuitableKeys):
            ToolKeyHandler().validate_and_decode(TOKEN)

    @patch.object(JWT, "unpack", return_value=UNPACK)
    @patch.object(JWS, "verify_compact", side_effect=BadSyntax(None, None))
    @patch.object(ToolKeyHandler, "_get_keyset", return_value=KEYSET)
    def test_validate_and_decode_bad_syntax(
        self,
        get_keyset_mock,
        verify_compact_mock,
        unpack_mock,
    ):
        """
        Check that the validate and decode raises BadSyntax on invalid token.
        """
        with self.assertRaises(exceptions.MalformedJwtToken):
            ToolKeyHandler().validate_and_decode(TOKEN)

    @patch.object(JWT, "unpack", return_value=UNPACK)
    @patch.object(JWS, "verify_compact", side_effect=WrongNumberOfParts)
    @patch.object(ToolKeyHandler, "_get_keyset", return_value=KEYSET)
    def test_validate_and_decode_wrong_number_of_parts(
        self,
        get_keyset_mock,
        verify_compact_mock,
        unpack_mock,
    ):
        """
        Check that the validate and decode raises WrongNumberOfParts on invalid token.
        """
        with self.assertRaises(exceptions.MalformedJwtToken):
            ToolKeyHandler().validate_and_decode(TOKEN)

    @patch.object(JWT, "unpack", return_value=UNPACK)
    @patch.object(JWS, "verify_compact", side_effect=BadSignature)
    @patch.object(ToolKeyHandler, "_get_keyset", return_value=KEYSET)
    def test_validate_and_decode_bad_signature(
        self,
        get_keyset_mock,
        verify_compact_mock,
        unpack_mock,
    ):
        """
        Check that the validate and decode raises BadSignature on invalid token.
        """
        with self.assertRaises(exceptions.BadJwtSignature):
            ToolKeyHandler().validate_and_decode(TOKEN)
