from unittest.mock import Mock, patch
from http import HTTPStatus

from django.urls import reverse
from django.test import Client, TestCase
from lti_store.models import (
    LTIVersion,
    ExternalLtiConfiguration,
)
from lti_store.key_handlers import PlatformKeyHandler, ToolKeyHandler
from lti_store.exceptions import (
    MalformedJwtToken,
    TokenSignatureExpired,
    NoSuitableKeys,
)

CONFIG_ID = 1
CLIENT_ID = "test-client-id"
PUBLIC_KEY = "test-public-key"
KEYSET_URL = "test-keyset-url"
PRIVATE_KEY = "test-private-key"
PRIVATE_KEY_ID = "test-private-key-id"
API_BASE = "test-lti-base"
JWT_TOKEN = "test-jwt-token"
ACCESS_TOKEN = "test-access-token"
EXPIRATION = 3600
SCOPES = [
    "https://purl.imsglobal.org/spec/lti-ags/scope/lineitem.readonly",
    "https://purl.imsglobal.org/spec/lti-ags/scope/lineitem",
    "https://purl.imsglobal.org/spec/lti-ags/scope/result.readonly",
    "https://purl.imsglobal.org/spec/lti-ags/scope/score",
    "https://purl.imsglobal.org/spec/lti-nrps/scope/contextmembership.readonly",
]
SCOPE_STR = " ".join(SCOPES)
CONTENT_TYPE = "application/x-www-form-urlencoded"


class TestAccessTokenEndpointView(TestCase):
    """Test access token endpoint view."""

    def setUp(self):
        """Test fixtures setup."""
        self.client = Client()
        self.url = reverse("access_token", kwargs={"lti_config_id": CONFIG_ID})
        self.external_config = Mock(
            version=LTIVersion.LTI_1P3,
            lti_1p3_client_id=CLIENT_ID,
            lti_1p3_tool_public_key=PUBLIC_KEY,
            lti_1p3_tool_keyset_url=KEYSET_URL,
            lti_1p3_private_key=PRIVATE_KEY,
            lti_1p3_private_key_id=PRIVATE_KEY_ID,
        )
        self.request_data = [
            ("grant_type", "client_credentials"),
            ("client_assertion_type", ""),
            ("client_assertion", JWT_TOKEN),
            ("scope", " ".join(list(map(str, SCOPES)))),
        ]

    @patch.object(ExternalLtiConfiguration, "objects")
    @patch("lti_store.views.urllib.parse.parse_qsl")
    @patch.object(ToolKeyHandler, "__init__", return_value=None)
    @patch.object(ToolKeyHandler, "validate_and_decode", return_value=None)
    @patch.object(PlatformKeyHandler, "__init__", return_value=None)
    @patch.object(PlatformKeyHandler, "encode_and_sign", return_value=ACCESS_TOKEN)
    @patch("lti_store.views.get_lti_api_base", return_value=API_BASE)
    def test_access_token_request(
        self,
        get_lti_api_base_mock,
        encode_and_sign_mock,
        platform_key_handler_mock,
        validate_and_decode_mock,
        tool_key_handler_mock,
        parse_qsl_mock,
        objects_mock,
    ):
        """Test access token request."""
        objects_mock.get.return_value = self.external_config
        parse_qsl_mock.return_value = self.request_data

        response = self.client.post(self.url, content_type=CONTENT_TYPE)

        self.assertJSONEqual(
            response.content,
            {
                "access_token": ACCESS_TOKEN,
                "token_type": "bearer",
                "expires_in": EXPIRATION,
                "scope": SCOPE_STR,
            },
        )
        self.assertEqual(response.status_code, 200)
        objects_mock.get.assert_called_once_with(id=CONFIG_ID)
        parse_qsl_mock.assert_called_once_with(
            response.wsgi_request.body.decode("utf-8"),
            keep_blank_values=True,
        )
        get_lti_api_base_mock.assert_called_once_with()
        tool_key_handler_mock.assert_called_once_with(
            public_key=PUBLIC_KEY,
            keyset_url=KEYSET_URL,
        )
        validate_and_decode_mock.assert_called_once_with(JWT_TOKEN)
        platform_key_handler_mock.assert_called_once_with(
            PRIVATE_KEY,
            PRIVATE_KEY_ID,
        )
        encode_and_sign_mock.assert_called_once_with(
            {
                "sub": CLIENT_ID,
                "iss": API_BASE,
                "scopes": SCOPE_STR,
            },
            expiration=EXPIRATION,
        )

    @patch.object(ExternalLtiConfiguration, "objects")
    @patch("lti_store.views.log.warning")
    def test_invalid_config_id(self, warning_mock, objects_mock):
        """Test request with invalid external configuration ID."""
        objects_mock.get.side_effect = ExternalLtiConfiguration.DoesNotExist

        response = self.client.post(self.url)

        self.assertEqual(response.status_code, HTTPStatus.NOT_FOUND)
        warning_mock.assert_called_once_with(
            "Can't find LTI external configuration with ID %s",
            CONFIG_ID,
        )

    @patch.object(ExternalLtiConfiguration, "objects")
    def test_invalid_lti_version(self, objects_mock):
        """Test request with invalid external configuration version."""
        self.external_config.version = LTIVersion.LTI_1P1
        objects_mock.get.return_value = self.external_config

        response = self.client.post(self.url)

        self.assertJSONEqual(
            response.content,
            {"error": "invalid_lti_version"},
        )
        self.assertEqual(response.status_code, HTTPStatus.BAD_REQUEST)

    @patch.object(ExternalLtiConfiguration, "objects")
    def test_missing_required_claim(self, objects_mock):
        """Test request with missing required claims."""
        objects_mock.get.return_value = self.external_config

        response = self.client.post(self.url)

        self.assertEqual(
            response.content.decode("utf-8"),
            '{"error": "invalid_request"}',
        )
        self.assertEqual(response.status_code, HTTPStatus.BAD_REQUEST)

    @patch.object(ExternalLtiConfiguration, "objects")
    @patch("lti_store.views.urllib.parse.parse_qsl")
    @patch.object(
        ToolKeyHandler,
        "__init__",
        return_value=None,
        side_effect=MalformedJwtToken,
    )
    def test_malformed_jwt_token(
        self,
        tool_key_handler_mock,
        parse_qsl_mock,
        objects_mock,
    ):
        """Test request with malformed JWT."""
        objects_mock.get.return_value = self.external_config
        parse_qsl_mock.return_value = self.request_data

        response = self.client.post(self.url, content_type=CONTENT_TYPE)

        self.assertEqual(
            response.content.decode("utf-8"),
            '{"error": "invalid_grant"}',
        )
        self.assertEqual(response.status_code, HTTPStatus.BAD_REQUEST)

    @patch.object(ExternalLtiConfiguration, "objects")
    @patch("lti_store.views.urllib.parse.parse_qsl")
    @patch.object(
        ToolKeyHandler,
        "__init__",
        return_value=None,
        side_effect=TokenSignatureExpired,
    )
    def test_token_signature_expired(
        self,
        tool_key_handler_mock,
        parse_qsl_mock,
        objects_mock,
    ):
        """Test request with expired token signature."""
        objects_mock.get.return_value = self.external_config
        parse_qsl_mock.return_value = self.request_data

        response = self.client.post(self.url, content_type=CONTENT_TYPE)

        self.assertEqual(
            response.content.decode("utf-8"),
            '{"error": "invalid_grant"}',
        )
        self.assertEqual(response.status_code, HTTPStatus.BAD_REQUEST)

    @patch.object(ExternalLtiConfiguration, "objects")
    @patch("lti_store.views.urllib.parse.parse_qsl")
    @patch.object(
        ToolKeyHandler,
        "__init__",
        return_value=None,
        side_effect=NoSuitableKeys,
    )
    def test_no_suitable_keys(
        self,
        tool_key_handler_mock,
        parse_qsl_mock,
        objects_mock,
    ):
        """Test request with no suitable keys."""
        objects_mock.get.return_value = self.external_config
        parse_qsl_mock.return_value = self.request_data

        response = self.client.post(self.url, content_type=CONTENT_TYPE)

        self.assertEqual(
            response.content.decode("utf-8"),
            '{"error": "invalid_client"}',
        )
        self.assertEqual(response.status_code, HTTPStatus.BAD_REQUEST)

    @patch.object(ExternalLtiConfiguration, "objects")
    @patch("lti_store.views.urllib.parse.parse_qsl")
    def test_unsupported_grant_type(self, parse_qsl_mock, objects_mock):
        request_data = self.request_data
        request_data.pop(0)
        request_data.append(("grant_type", "unsuported"))
        parse_qsl_mock.return_value = request_data
        objects_mock.get.return_value = self.external_config

        response = self.client.post(self.url, content_type=CONTENT_TYPE)

        self.assertEqual(
            response.content.decode("utf-8"),
            '{"error": "unsupported_grant_type"}',
        )
        self.assertEqual(response.status_code, HTTPStatus.BAD_REQUEST)


class TestPublicKeysetEndpointView(TestCase):
    """Test public keyset endpoint view."""

    def setUp(self):
        """Test fixtures setup."""
        self.client = Client()
        self.url = reverse("public_keyset", kwargs={"lti_config_id": CONFIG_ID})
        self.external_config = Mock(
            version=LTIVersion.LTI_1P3,
            lti_1p3_public_jwk={"test": "test"},
        )

    @patch.object(ExternalLtiConfiguration, "objects")
    @patch("lti_store.views.ast.literal_eval")
    def test_public_keyset_request(
        self,
        literal_eval_mock,
        objects_mock,
    ):
        """Test public keyset request."""
        objects_mock.get.return_value = self.external_config
        literal_eval_mock.return_value = self.external_config.lti_1p3_public_jwk
        response = self.client.get(self.url)

        self.assertJSONEqual(
            response.content,
            self.external_config.lti_1p3_public_jwk,
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.headers["Content-Disposition"], "attachment; filename=keyset.json"
        )
        objects_mock.get.assert_called_once_with(id=CONFIG_ID)
        literal_eval_mock.assert_called_once_with(
            self.external_config.lti_1p3_public_jwk
        )

    @patch.object(ExternalLtiConfiguration, "objects")
    @patch("lti_store.views.log.warning")
    def test_invalid_config_id(self, warning_mock, objects_mock):
        """Test request with invalid external configuration ID."""
        objects_mock.get.side_effect = ExternalLtiConfiguration.DoesNotExist

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 404)
        warning_mock.assert_called_once_with(
            "Can't find LTI external configuration with ID %s",
            CONFIG_ID,
        )

    @patch.object(ExternalLtiConfiguration, "objects")
    def test_invalid_lti_version(self, objects_mock):
        """Test request with invalid external configuration version."""
        self.external_config.version = LTIVersion.LTI_1P1
        objects_mock.get.return_value = self.external_config

        response = self.client.get(self.url)

        self.assertJSONEqual(
            response.content,
            {"error": "invalid_lti_version"},
        )
        self.assertEqual(response.status_code, HTTPStatus.BAD_REQUEST)
