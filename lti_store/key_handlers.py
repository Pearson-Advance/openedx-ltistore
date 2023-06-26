"""LTI 1.3 - Key handlers.

This module handles validating messages sent by the tool, generating
access tokens and generating the platform public keyset.
"""
import codecs
import copy
import time
import json

from Cryptodome.PublicKey import RSA
from jwkest import BadSignature, BadSyntax, WrongNumberOfParts, jwk
from jwkest.jwk import RSAKey, load_jwks_from_url
from jwkest.jws import JWS, NoSuitableSigningKeys
from jwkest.jwt import JWT

from lti_store.exceptions import (
    RsaKeyNotSet,
    InvalidRsaKey,
    NoSuitableKeys,
    TokenSignatureExpired,
    MalformedJwtToken,
    BadJwtSignature,
    InvalidClaimValue,
)


class ToolKeyHandler:
    """LTI 1.3 Tool JWT Handler.

    Uses a tool public keys or keysets URL to retrieve
    a key and validate a message sent by the tool.

    This is primarily used by the Access Token endpoint
    in order to validate the JWT Signature of messages
    signed with the tools signature.

    Attributes:
        keyset_url (:obj:`str`, optional): Tool Keyset URL.
        public_key (:obj:`str`, optional): Tool Public Key.

    """

    def __init__(self, public_key=None, keyset_url=None):
        """Instance message validator.

        Import a public key from the tool by either using a keyset url
        or a combination of public key + key id.

        Keyset URL takes precedence because it makes key rotation easier to do.

        Args:
            public_key (:obj:`str`, optional): Tool Public Key.
            keyset_url (:obj:`str`, optional): Tool Keyset URL.

        Raises:
            InvalidRsaKey: Invalid public key loaded.

        """
        # Only store keyset URL to avoid blocking the class
        # instancing on an external url, which is only used
        # when validating a token.
        self.keyset_url = keyset_url
        self.public_key = None

        if public_key:
            try:
                # Import key and save to internal state.
                new_key = RSAKey(use="sig")
                new_key.load_key(
                    RSA.import_key(codecs.decode(public_key, "unicode_escape")),
                )
                self.public_key = new_key
            except ValueError as err:
                raise InvalidRsaKey() from err

    def _get_keyset(self, key_id=None):
        """Get keyset from available sources.

        If using a RSA key, forcefully set the key id
        to match the one from the JWT token.

        Args:
            key_id (:obj:`str`, optional): Private Key ID.

        Raises:
            NoSuitableKeys: jwkest fails to load keyset URL.

        """
        keyset = []

        if self.keyset_url:
            try:
                keys = load_jwks_from_url(self.keyset_url)
                keyset.extend(keys)
            except Exception as err:
                # Broad Exception is required here because jwkest raises
                # an Exception object explicitly.
                # Beware that many different scenarios are being handled
                # as an invalid key when the JWK loading fails.
                raise NoSuitableKeys() from err

        if self.public_key and key_id:
            # Fill in key id of stored key.
            # This is needed because if the JWS is signed with a
            # key with a kid, pyjwkest doesn't match them with
            # keys without kid (kid=None) and fails verification
            self.public_key.kid = key_id

            # Add to keyset.
            keyset.append(self.public_key)

        return keyset

    def validate_and_decode(self, token):
        """Check if a message sent by the tool is valid.

        The authorization server decodes the JWT and MUST validate the values for the
        iss, sub, exp, aud and jti claims.

        Args:
            token (str): JWT Token.

        Raises:
            TokenSignatureExpired: JWT token signature is expired.
            NoSuitableKeys: JWKS could not be loaded.
            MalformedJwtToken: JWT token is malformed.
            BadJwtSignature: JWT token signature is invalid.

        References:
            https://www.imsglobal.org/spec/security/v1p0/#using-oauth-2-0-client-credentials-grant

        """
        try:
            # Get kid from JWT header.
            jwt = JWT().unpack(token)

            # Verify message signature.
            message = JWS().verify_compact(
                token,
                keys=self._get_keyset(jwt.headers.get("kid")),
            )

            # If message is valid, check expiration from JWT.
            if "exp" in message and message.get("exp") < time.time():
                raise TokenSignatureExpired()

            # Return decoded message.
            return message
        except NoSuitableSigningKeys as err:
            raise NoSuitableKeys() from err
        except (BadSyntax, WrongNumberOfParts) as err:
            raise MalformedJwtToken() from err
        except BadSignature as err:
            raise BadJwtSignature() from err


class PlatformKeyHandler:
    """Platform RSA Key handler.

    This class loads the platform key and is responsible for
    encoding JWT messages and exporting public keys.

    Attributes:
        key (:obj:`str`, optional): RSA Key.

    """

    def __init__(self, key_pem, key_id=None):
        """Import key when instancing class if a key is present.

        Args:
            key_pem (str): RSA Private Key PEM.
            key_id (:obj:`str`, optional): Private Key ID.

        Raises:
            InvalidRsaKey: Failed to import key.

        """
        self.key = None

        if key_pem:
            # Import JWK from RSA key.
            try:
                self.key = RSAKey(
                    kid=key_id,
                    key=RSA.import_key(key_pem),
                )
            except ValueError:
                raise InvalidRsaKey()

    def encode_and_sign(self, message, expiration=None):
        """Encode and sign JSON with RSA key.

        Args:
            message (str): Message to encode.
            expiration (:obj:`int`, optional): Token expiration.

        Raises:
            RsaKeyNotSet: RSA key is not set.

        """
        if not self.key:
            raise RsaKeyNotSet()

        message_copy = copy.deepcopy(message)

        # Set iat and exp if expiration is set.
        # https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.6
        # https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.4
        if expiration:
            message_copy.update(
                {
                    "iat": int(round(time.time())),
                    "exp": int(round(time.time()) + expiration),
                },
            )

        # The class instance that sets up the signing operation
        # An RS 256 key is required for LTI 1.3
        jws = JWS(message_copy, alg="RS256", cty="JWT")

        # Encode and sign LTI message.
        return jws.sign_compact([self.key])

    def get_public_jwk(self):
        """Export Public JWK."""
        # Return empty keyset if no key is set.
        if not self.key:
            return {"keys": []}

        public_keys = jwk.KEYS()
        public_keys.append(self.key)

        return json.loads(public_keys.dump_jwks())

    def validate_and_decode(self, token, iss=None, aud=None):
        """Check if a platform token is valid, and return allowed scopes.

        Validates a token sent by the tool using the platform's RSA Key.
        Optionally validate iss and aud claims if provided.

        Args:
            token (str): JWT Token.
            iss (:obj:`str`, optional): Issuer.
            aud (:obj:`str`, optional): Client ID.

        Raises:
            TokenSignatureExpired: RSA key is not set.
            InvalidClaimValue: Missing iss or aud, iss value not expected.
            NoSuitableKeys: JWKS could not be loaded.
            MalformedJwtToken: JWT token malformed.

        """
        try:
            # Verify message signature.
            message = JWS().verify_compact(token, keys=[self.key])

            # If message is valid, check expiration from JWT.
            if "exp" in message and message.get("exp") < time.time():
                raise TokenSignatureExpired()

            # Validate issuer claim (if present).
            if iss and ("iss" not in message or message.get("iss") != iss):
                raise InvalidClaimValue(
                    "The required iss claim is either missing or does "
                    "not match the expected iss value."
                )

            # Validate audience claim (if present).
            if aud and ("aud" not in message or aud not in message.get("aud")):
                raise InvalidClaimValue("The required aud claim is missing.")

            # Return token contents.
            return message
        except NoSuitableSigningKeys as err:
            raise NoSuitableKeys() from err
        except BadSyntax as err:
            raise MalformedJwtToken() from err
