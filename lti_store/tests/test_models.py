from django.core.exceptions import ValidationError
from django.test import TestCase
from unittest.mock import patch, call
from lti_store.models import ExternalLtiConfiguration, LTIVersion, MESSAGES


class LTIConfigurationTestCase(TestCase):

    REQUIRED_FIELDS = {
        "name": "Test Config",
        "slug": "test-config",
    }
    UUID4 = "test-uuid4"
    PRIVATE_KEY = "test-private-key"
    PUBLIC_KEY = "test-public-key"
    PUBLIC_JWK = "test-public-jwk"

    def test_string_representation_of_model(self):
        config = ExternalLtiConfiguration.objects.create(**self.REQUIRED_FIELDS)
        self.assertEqual(
            str(config),
            f"<ExternalLtiConfiguration #1: {self.REQUIRED_FIELDS['slug']}>",
        )

    def test_1p1_missing_fields(self):
        """Test clean method on a LTI 1.1 configuration with missing fields."""
        with self.assertRaises(ValidationError) as exc:
            ExternalLtiConfiguration(
                **self.REQUIRED_FIELDS,
                version=LTIVersion.LTI_1P1,
            ).clean()

        self.assertEqual(
            str(exc.exception),
            str(
                {
                    "lti_1p1_launch_url": [MESSAGES["required"]],
                    "lti_1p1_client_key": [MESSAGES["required"]],
                    "lti_1p1_client_secret": [MESSAGES["required"]],
                },
            ),
        )

    def test_1p3_missing_private_key(self):
        """Test clean method on a LTI 1.3 configuration with missing private key."""
        with self.assertRaises(ValidationError) as exc:
            ExternalLtiConfiguration(
                **self.REQUIRED_FIELDS,
                version=LTIVersion.LTI_1P3,
                lti_1p3_tool_public_key=self.PUBLIC_KEY,
            ).clean()

        self.assertEqual(
            str(exc.exception),
            str(
                {
                    "lti_1p3_private_key": [MESSAGES["required"]],
                },
            ),
        )

    def test_1p3_invalid_private_key(self):
        """Test clean method on a LTI 1.3 configuration with invalid private key."""
        with self.assertRaises(ValidationError) as exc:
            ExternalLtiConfiguration(
                **self.REQUIRED_FIELDS,
                version=LTIVersion.LTI_1P3,
                lti_1p3_private_key="invalid-private-key",
                lti_1p3_tool_public_key=self.PUBLIC_KEY,
            ).full_clean()

        self.assertEqual(
            str(exc.exception),
            str(
                {
                    "lti_1p3_private_key": [MESSAGES["invalid_private_key"]],
                },
            ),
        )

    def test_1p3_missing_public_key_and_keyset_url(self):
        """Test clean method on a LTI 1.3 configuration with missing public key or keyset URL."""
        with self.assertRaises(ValidationError) as exc:
            ExternalLtiConfiguration(
                **self.REQUIRED_FIELDS,
                version=LTIVersion.LTI_1P3,
                lti_1p3_private_key=self.PRIVATE_KEY,
            ).clean()

        self.assertEqual(
            str(exc.exception),
            str(
                {
                    "lti_1p3_tool_public_key": [MESSAGES["required_pubkey_or_keyset"]],
                    "lti_1p3_tool_keyset_url": [MESSAGES["required_pubkey_or_keyset"]],
                },
            ),
        )

    @patch("lti_store.models.get_public_jwk")
    @patch("lti_store.models.uuid.uuid4")
    def test_1p3_save(self, uuid4_mock, get_public_jwk_mock):
        """Test save method on a LTI 1.3 configuration."""
        uuid4_mock.return_value = self.UUID4
        get_public_jwk_mock.return_value = self.PUBLIC_JWK

        config = ExternalLtiConfiguration(
            **self.REQUIRED_FIELDS,
            version=LTIVersion.LTI_1P3,
            lti_1p3_private_key=self.PRIVATE_KEY,
            lti_1p3_tool_public_key=self.PUBLIC_KEY,
        )
        config.save()

        self.assertEqual(config.lti_1p3_client_id, self.UUID4)
        self.assertEqual(config.lti_1p3_private_key_id, self.UUID4)
        self.assertEqual(config.lti_1p3_public_jwk, self.PUBLIC_JWK)
        uuid4_mock.assert_has_calls([call(), call()])
        get_public_jwk_mock.assert_called_once_with(
            self.PRIVATE_KEY, config.lti_1p3_private_key_id,
        )
