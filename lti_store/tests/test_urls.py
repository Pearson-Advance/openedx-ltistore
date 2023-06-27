from django.test import TestCase
from django.urls import resolve, reverse

from lti_store.views import access_token_endpoint


class TestUrls(TestCase):
    """Test URL configuration."""

    def test_lti_tool_login_url_resolves(self):
        """Test access_token_endpoint URL can be resolved."""
        self.assertEqual(
            resolve(reverse("access_token", kwargs={"lti_config_id": 1})).func,
            access_token_endpoint,
        )
