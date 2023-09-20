import requests
import urllib3
import ssl
import traceback
import logging
from cryptography.exceptions import InvalidTag
from robot.libraries.BuiltIn import BuiltIn, RobotNotRunningError

from RPA.Robocorp.Vault import Vault, RobocorpVault, RobocorpVaultError, Secret
from RPA.core.helpers import required_env


class CustomHttpAdapter(requests.adapters.HTTPAdapter):
    # "Transport adapter" that allows us to use custom ssl_context.

    def __init__(self, ssl_context=None, **kwargs):
        self.ssl_context = ssl_context
        super().__init__(**kwargs)

    def init_poolmanager(self, connections, maxsize, block=False):
        self.poolmanager = urllib3.poolmanager.PoolManager(
            num_pools=connections,
            maxsize=maxsize,
            block=block,
            ssl_context=self.ssl_context,
        )


def get_legacy_session():
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    ctx.options |= 0x4  # OP_LEGACY_SERVER_CONNECT
    session = requests.session()
    session.mount("https://", CustomHttpAdapter(ctx))
    return session


class LegacyRobocorpVault(RobocorpVault):
    """Uses a legacy SSL context to allow vault to connect when
    in an environment that does not support Python <3.10 but
    also requires OpenSSL 1.1.1v style TLS connections.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._ssl_session = get_legacy_session()

    def get_publickey(self) -> bytes:
        """Get the public key for AES encryption with the existing token
        utilizing the legacy SSL context."""
        url = self.create_public_key_url()
        try:
            response = self._ssl_session.get(url, headers=self.headers)
            response.raise_for_status()
        except Exception as e:
            self.logger.debug(traceback.format_exc())
            raise RobocorpVaultError(
                "Failed to fetch public key. Is your token valid?"
            ) from e

        return response.content

    def get_secret(self, secret_name: str) -> str:
        """Get secret defined with given name from Robocorp Vault utilizing
        the legacy SSL context.

        :param secret_name:         Name of secret to fetch
        :returns:                   Secret object
        :raises RobocorpVaultError: Error with API request or response payload
        """
        url = self.create_secret_url(secret_name)

        try:
            response = self._ssl_session.get(
                url, headers=self.headers, params=self.params
            )
            response.raise_for_status()

            payload = response.json()
            payload = self._decrypt_payload(payload)
        except InvalidTag as e:
            self.logger.debug(traceback.format_exc())
            raise RobocorpVaultError("Failed to validate authentication tag") from e
        except Exception as exc:
            self.logger.debug(traceback.format_exc())
            raise RobocorpVaultError from exc

        return Secret(payload["name"], payload["description"], payload["values"])

    def set_secret(self, secret: Secret) -> None:
        """Set the secret value in the Vault utilizing the legacy SSL
        context. Note that the secret possibly consists of multiple
        key-value pairs, which will all be overwritten with the values
        given here. So don't try to update only one item of the secret,
        update all of them.

        :param secret: A ``Secret`` object
        """
        value, aes_iv, aes_key, aes_tag = self._encrypt_secret_value_with_aes(secret)
        pub_key = self.get_publickey()
        aes_enc = self._encrypt_aes_key_with_public_rsa(aes_key, pub_key)

        payload = {
            "description": secret.description,
            "encryption": {
                "authTag": aes_tag.decode(),
                "encryptedAES": aes_enc.decode(),
                "encryptionScheme": self.ENCRYPTION_SCHEME,
                "iv": aes_iv.decode(),
            },
            "name": secret.name,
            "value": value.decode(),
        }

        url = self.create_secret_url(secret.name)
        try:
            response = self._ssl_session.put(url, headers=self.headers, json=payload)
            response.raise_for_status()
        except Exception as e:
            self.logger.debug(traceback.format_exc())
            if response.status_code == 403:
                raise RobocorpVaultError(
                    "Failed to set secret value. Does your token have write access?"
                ) from e
            raise RobocorpVaultError("Failed to set secret value.") from e


class LegacyVault(Vault):
    __doc__ = f"""`LegacyVault` is an extension of the `Vault` library
    that uses a legacy SSL context to allow vault to connect when
    in an environment that requires Python >=3.10 but also requires
    OpenSSL 1.1.1v style TLS connections. The full `Vault` documentation
    is included here for convenience.

    {Vault.__doc__}
    """

    def __init__(self, *args, **kwargs):
        """The selected adapter can be set with the environment variable
        ``RPA_SECRET_MANAGER``, or the keyword argument ``default_adapter``.
        Defaults to Robocorp Vault if not defined.

        All other library arguments are passed to the adapter.

        :param default_adapter: Override default secret adapter
        :param disable_listener: Disable log listener. Defaults to False.
            Disabling the listener is useful when using the library in
            debug mode, as the listener will otherwise cause keywords
            in this library to be hidden from the log.
        """
        self.logger = logging.getLogger(__name__)

        default = kwargs.pop("default_adapter", RobocorpVault)
        adapter = required_env("RPA_SECRET_MANAGER", default)

        self._adapter_factory = self._create_factory(adapter, args, kwargs)
        self._adapter = None

        if kwargs.pop("disable_listener", False):
            return
        try:
            BuiltIn().import_library("RPA.RobotLogListener")
        except RobotNotRunningError:
            pass
