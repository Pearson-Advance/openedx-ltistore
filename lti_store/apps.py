from django.apps import AppConfig


class LtiStoreConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "lti_store"
    plugin_app = {
        "url_config": {
            "lms.djangoapp": {
                "namespace": name,
                "regex": f"^{name}/",
                "relative_path": "urls",
            },
        },
    }
