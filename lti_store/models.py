import uuid
import urllib

from django.db import models
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _
from Cryptodome.PublicKey import RSA
from lti_store.key_handlers import PlatformKeyHandler

from lti_store.apps import LtiStoreConfig
from lti_store.utils import get_lti_api_base

MESSAGES = {
    "required": "This field is required.",
    "required_pubkey_or_keyset": "LTI 1.3 requires either a public key or a keyset URL.",
    "invalid_private_key": "Invalid private key format.",
}


def validate_private_key(key):
    """Validate private key format."""
    try:
        RSA.import_key(key)
    except ValueError:
        raise ValidationError(_(MESSAGES["invalid_private_key"]))

    return key


class LTIVersion(models.TextChoices):
    LTI_1P1 = "lti_1p1", _("LTI 1.1")
    LTI_1P3 = "lti_1p3", _("LTI 1.3")


class ExternalLtiConfiguration(models.Model):

    name = models.CharField(max_length=80, unique=True)
    slug = models.SlugField(max_length=80, unique=True)
    description = models.TextField(blank=True, default="")

    version = models.CharField(
        max_length=10, choices=LTIVersion.choices, default=LTIVersion.LTI_1P1
    )

    # LTI 1.1 Related variables
    lti_1p1_launch_url = models.CharField(
        max_length=255,
        blank=True,
        help_text=_("The URL of the external tool that initiates the launch."),
    )
    lti_1p1_client_key = models.CharField(
        max_length=255,
        blank=True,
        help_text=_("Client key provided by the LTI tool provider."),
    )

    lti_1p1_client_secret = models.CharField(
        max_length=255,
        blank=True,
        help_text=_("Client secret provided by the LTI tool provider."),
    )

    # LTI 1.3 Related variables
    lti_1p3_client_id = models.CharField(
        "LTI 1.3 Client ID",
        max_length=255,
        blank=True,
        help_text=_("Client ID used by LTI tool"),
    )
    lti_1p3_deployment_id = models.CharField(
        "LTI 1.3 Deployment ID",
        max_length=255,
        blank=True,
        help_text=_("Deployment ID used by LTI tool"),
    )
    lti_1p3_oidc_url = models.CharField(
        "LTI 1.3 OIDC URL",
        max_length=255,
        blank=True,
        help_text=_("""This is the OIDC third-party initiated login endpoint URL in the LTI 1.3 flow,
        which should be provided by the LTI Tool."""),
    )
    lti_1p3_launch_url = models.CharField(
        "LTI 1.3 Launch URL",
        max_length=255,
        blank=True,
        help_text=_("""This is the LTI launch URL, otherwise known as the target_link_uri.
        It represents the LTI resource to launch to or load in the second leg of the launch flow,
        when the resource is actually launched or loaded."""),
    )
    lti_1p3_private_key = models.TextField(
        "LTI 1.3 Private Key",
        blank=True,
        help_text=_("Platform's generated Private key. Keep this value secret."),
        validators=[validate_private_key],
    )
    lti_1p3_private_key_id = models.CharField(
        "LTI 1.3 Private Key ID",
        max_length=255,
        blank=True,
        help_text=_("Platform's generated Private key ID"),
    )
    lti_1p3_tool_public_key = models.TextField(
        "LTI 1.3 Tool Public Key",
        blank=True,
        help_text=_("""This is the LTI Tool's public key.
        This should be provided by the LTI Tool.
        One of either lti_1p3_tool_public_key or
        lti_1p3_tool_keyset_url must not be blank."""),
    )
    lti_1p3_tool_keyset_url = models.URLField(
        "LTI 1.3 Tool Keyset URL",
        max_length=255,
        blank=True,
        help_text=_("""This is the LTI Tool's JWK (JSON Web Key)
        Keyset (JWKS) URL. This should be provided by the LTI
        Tool. One of either lti_1p3_tool_public_key or
        lti_1p3_tool_keyset_url must not be blank."""),
    )
    lti_1p3_public_jwk = models.TextField(
        "LTI 1.3 Public JWK",
        blank=True,
        help_text=_("Platform's generated JWK keyset."),
    )

    def __str__(self):
        return f"<ExternalLtiConfiguration #{self.id}: {self.slug}>"

    @property
    def lti_1p3_access_token_url(self):
        """LTI 1.3 Access Token URL.

        This property returns a string with the URL of
        this configuration access token.
        """
        return urllib.parse.urljoin(
            get_lti_api_base(),
            f"/{LtiStoreConfig.name}/token/{self.pk}",
        )

    @property
    def lti_1p3_keyset_url(self):
        """LTI 1.3 Keyset URL.

        This property returns a string with the URL of
        this configuration keyset.
        """
        return urllib.parse.urljoin(
            get_lti_api_base(),
            f"/{LtiStoreConfig.name}/public_keyset/{self.pk}",
        )

    def clean(self):
        validation_errors = {}

        if self.version == LTIVersion.LTI_1P1:
            for field in [
                "lti_1p1_launch_url",
                "lti_1p1_client_key",
                "lti_1p1_client_secret",
            ]:
                # Raise ValidationError exception for any missing LTI 1.1 field.
                if not getattr(self, field):
                    validation_errors.update({field: _(MESSAGES["required"])})

        if self.version == LTIVersion.LTI_1P3:
            if not self.lti_1p3_private_key:
                # Raise ValidationError if private key is missing.
                validation_errors.update(
                    {"lti_1p3_private_key": _(MESSAGES["required"])},
                )
            if not self.lti_1p3_tool_public_key and not self.lti_1p3_tool_keyset_url:
                # Raise ValidationError if public key and keyset URL are missing.
                validation_errors.update(
                    {
                        "lti_1p3_tool_public_key": _(
                            MESSAGES["required_pubkey_or_keyset"]
                        ),
                        "lti_1p3_tool_keyset_url": _(
                            MESSAGES["required_pubkey_or_keyset"]
                        ),
                    },
                )

        if validation_errors:
            raise ValidationError(validation_errors)

    def save(self, *args, **kwargs):
        if self.version == LTIVersion.LTI_1P3:
            # Generate client ID or private key ID if missing.
            if not self.lti_1p3_client_id:
                self.lti_1p3_client_id = str(uuid.uuid4())
            if not self.lti_1p3_private_key_id:
                self.lti_1p3_private_key_id = str(uuid.uuid4())

            # Regenerate public JWK.
            key_handler = PlatformKeyHandler(
                key_pem=self.lti_1p3_private_key,
                key_id=self.lti_1p3_private_key_id,
            )
            self.lti_1p3_public_jwk = key_handler.get_public_jwk()

        super().save(*args, **kwargs)
