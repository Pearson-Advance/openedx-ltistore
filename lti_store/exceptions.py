"""Custom exceptions for lti_store app."""


class Lti1p3Exception(Exception):
    """Base exception for LTI 1.3."""

    message = None

    def __init__(self, message=None):
        if not message:
            message = self.message
        super().__init__(message)


class TokenSignatureExpired(Lti1p3Exception):
    message = "The token signature has expired."


class NoSuitableKeys(Lti1p3Exception):
    message = "JWKS could not be loaded from the URL."


class BadJwtSignature(Lti1p3Exception):
    message = "The JWT signature is invalid."


class MalformedJwtToken(Lti1p3Exception):
    message = "The JWT could not be parsed because it is malformed."


class MissingRequiredClaim(Lti1p3Exception):
    message = "The required claim is missing."


class UnsupportedGrantType(Lti1p3Exception):
    message = "The JWT grant_type is unsupported."


class InvalidClaimValue(Lti1p3Exception):
    message = "The claim has an invalid value."


class InvalidRsaKey(Lti1p3Exception):
    message = "The RSA key could not parsed."


class RsaKeyNotSet(Lti1p3Exception):
    message = "The RSA key is not set."
