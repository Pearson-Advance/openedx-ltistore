from django.test import TestCase, override_settings

from lti_store.utils import get_lti_api_base


class TestUtils(TestCase):
    """Test utils functions."""

    def test_get_lti_api_base(self):
        """Test get_lti_api base function."""
        with override_settings(LTI_API_BASE="test-lti-api-base"):
            self.assertEqual(get_lti_api_base(), "test-lti-api-base")

        with override_settings(LTI_BASE="test-lti-base"):
            self.assertEqual(get_lti_api_base(), "test-lti-base")

        with override_settings(LMS_ROOT_URL="test-lms-root-url"):
            self.assertEqual(get_lti_api_base(), "test-lms-root-url")
