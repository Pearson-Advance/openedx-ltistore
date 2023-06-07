from django.urls import path

from lti_store.views import access_token_endpoint, public_keyset_endpoint

urlpatterns = [
    path(
        "token/<int:lti_config_id>",
        access_token_endpoint,
        name="access_token",
    ),
    path(
        'public_keyset/<int:lti_config_id>',
        public_keyset_endpoint,
        name='public_keyset',
    ),
]
