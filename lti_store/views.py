import logging
import urllib
import ast
from http import HTTPStatus

from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.views.decorators.clickjacking import xframe_options_sameorigin
from django.http import Http404, JsonResponse
from lti_store.exceptions import (
    MissingRequiredClaim,
    UnsupportedGrantType,
    MalformedJwtToken,
    TokenSignatureExpired,
    NoSuitableKeys,
)
from lti_store.models import ExternalLtiConfiguration, LTIVersion
from lti_store.key_handlers import PlatformKeyHandler, ToolKeyHandler
from lti_store.utils import get_lti_api_base

log = logging.getLogger(__name__)

LTI_1P3_ACCESS_TOKEN_REQUIRED_CLAIMS = {
    "grant_type",
    "client_assertion_type",
    "client_assertion",
    "scope",
}

LTI_1P3_ACCESS_TOKEN_SCOPES = [
    # LTI-AGS Scopes
    "https://purl.imsglobal.org/spec/lti-ags/scope/lineitem.readonly",
    "https://purl.imsglobal.org/spec/lti-ags/scope/lineitem",
    "https://purl.imsglobal.org/spec/lti-ags/scope/result.readonly",
    "https://purl.imsglobal.org/spec/lti-ags/scope/score",
    # LTI-NRPS Scopes
    "https://purl.imsglobal.org/spec/lti-nrps/scope/contextmembership.readonly",
]

LTI_CONFIG_404_MESSAGE = "Can't find LTI external configuration with ID %s"


@csrf_exempt
@xframe_options_sameorigin
@require_http_methods(["POST"])
def access_token_endpoint(request, lti_config_id):
    """Gate endpoint to enable tools to retrieve access tokens for the LTI 1.3 tool.

    Arguments:
        lti_config_id (int): ID of the LTI external configuration

    Returns:
        JsonResponse with access token or error message

    Raises:
        Http404: LTI external configuration is not found
        MissingRequiredClaim: Required claims are missing from request data
        UnsupportedGrantType: Unsupported grant type on request data

    References:
        Sucess: https://tools.ietf.org/html/rfc6749#section-4.4.3
        Failure: https://tools.ietf.org/html/rfc6749#section-5.2

    """

    try:
        config = ExternalLtiConfiguration.objects.get(id=lti_config_id)
    except ExternalLtiConfiguration.DoesNotExist as exc:
        log.warning(LTI_CONFIG_404_MESSAGE, lti_config_id)
        raise Http404 from exc

    if config.version != LTIVersion.LTI_1P3:
        return JsonResponse(
            {"error": "invalid_lti_version"},
            status=HTTPStatus.BAD_REQUEST,
        )

    # Transform request data to dictionary.
    token_request_data = dict(
        urllib.parse.parse_qsl(
            request.body.decode("utf-8"),
            keep_blank_values=True,
        ),
    )

    try:
        # Check if all required claims are on request data.
        for required_claim in LTI_1P3_ACCESS_TOKEN_REQUIRED_CLAIMS:
            if required_claim not in token_request_data.keys():
                raise MissingRequiredClaim(
                    f"The required claim {required_claim} is missing from the JWT.",
                )

        # Check that grant type is `client_credentials`.
        if not token_request_data.get("grant_type") == "client_credentials":
            raise UnsupportedGrantType()

        # Validate JWT token.
        tool_jwt = ToolKeyHandler(
            public_key=config.lti_1p3_tool_public_key,
            keyset_url=config.lti_1p3_tool_keyset_url,
        )
        tool_jwt.validate_and_decode(token_request_data.get("client_assertion"))

        # Get platform key handler.
        key_handler = PlatformKeyHandler(
            config.lti_1p3_private_key,
            config.lti_1p3_private_key_id,
        )

        # Check scopes and only return valid and supported ones.
        valid_scopes = []
        requested_scopes = token_request_data.get("scope").split(" ")

        for scope in requested_scopes:
            if scope in LTI_1P3_ACCESS_TOKEN_SCOPES:
                valid_scopes.append(scope)

        # Scopes are space separated as described in https://tools.ietf.org/html/rfc6749
        scopes_str = " ".join(valid_scopes)

        # This response is compliant with RFC 6749
        # https://tools.ietf.org/html/rfc6749#section-4.4.3
        return JsonResponse(
            {
                "access_token": key_handler.encode_and_sign(
                    {
                        "sub": config.lti_1p3_client_id,
                        "iss": get_lti_api_base(),
                        "scopes": scopes_str,
                    },
                    # Create token valid for 3600 seconds (1h) as per specification
                    # https://www.imsglobal.org/spec/security/v1p0/#expires_in-values-and-renewing-the-access-token
                    expiration=3600,
                ),
                "token_type": "bearer",
                "expires_in": 3600,
                "scope": scopes_str,
            },
        )

    # Handle errors and return a proper response.
    except MissingRequiredClaim:
        # Missing required request attibutes.
        return JsonResponse({"error": "invalid_request"}, status=HTTPStatus.BAD_REQUEST)
    except (MalformedJwtToken, TokenSignatureExpired):
        # Invalid malformed grant token or token expired.
        return JsonResponse({"error": "invalid_grant"}, status=HTTPStatus.BAD_REQUEST)
    except NoSuitableKeys:
        # Can't validate token using available keys.
        return JsonResponse({"error": "invalid_client"}, status=HTTPStatus.BAD_REQUEST)
    except UnsupportedGrantType:
        # Requested grant type is unsupported.
        return JsonResponse(
            {"error": "unsupported_grant_type"},
            status=HTTPStatus.BAD_REQUEST,
        )


@require_http_methods(["GET"])
def public_keyset_endpoint(request, lti_config_id):
    """Gate endpoint to fetch public keysets.

    Arguments:
        lti_config_id (int): ID of the LTI external configuration

    Returns:
        JsonResponse with public keyset

    Raises:
        Http404: LTI external configuration is not found

    """
    try:
        config = ExternalLtiConfiguration.objects.get(id=lti_config_id)

        if config.version != LTIVersion.LTI_1P3:
            return JsonResponse(
                {"error": "invalid_lti_version"},
                status=HTTPStatus.BAD_REQUEST,
            )

        # Return public JWK.
        response = JsonResponse(
            ast.literal_eval(config.lti_1p3_public_jwk),
            headers={"Content-Disposition": "attachment; filename=keyset.json"},
        )

        return response
    except ExternalLtiConfiguration.DoesNotExist as exc:
        log.warning(LTI_CONFIG_404_MESSAGE, lti_config_id)
        raise Http404 from exc
