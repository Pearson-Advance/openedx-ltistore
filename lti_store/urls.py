from django.urls import path

from lti_store.views import access_token_endpoint

urlpatterns = [
    path(
        "token/<int:lti_config_id>",
        access_token_endpoint,
        name="access_token",
    ),
]
