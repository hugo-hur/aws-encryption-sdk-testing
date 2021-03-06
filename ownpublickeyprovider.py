import aws_encryption_sdk
from aws_encryption_sdk.key_providers.raw import RawMasterKey
from aws_encryption_sdk.internal.crypto.wrapping_keys import WrappingKey
from aws_encryption_sdk.key_providers.raw import RawMasterKeyProvider
from aws_encryption_sdk.identifiers import CommitmentPolicy, EncryptionKeyType, WrappingAlgorithm

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric import rsa

"""class OwnPublicKeyProvider(RawMasterKeyProvider):
    
    def __init__(self, **kwargs):
        self._keys = {}

    def _get_raw_key(self, key_id):
        public_key_pem = None
        with open(key_id, "rb") as key_file:
            public_key_pem = key_file.read()
            #self._public_keys[key_id] = public_key

        return WrappingKey(
                    wrapping_key=public_key_pem,
                    wrapping_key_type=EncryptionKeyType.PUBLIC,
                    # The wrapping algorithm tells the raw RSA master key
                    # how to use your wrapping key to encrypt data keys.
                    #
                    # We recommend using RSA_OAEP_SHA256_MGF1.
                    # You should not use RSA_PKCS1 unless you require it for backwards compatibility.
                    wrapping_algorithm=WrappingAlgorithm.RSA_OAEP_SHA256_MGF1
                )
"""

class OwnPublicKeyProvider(RawMasterKeyProvider):
    """Randomly generates and provides 4096-bit RSA keys consistently per unique key id."""

    provider_id = "own-public"

    def __init__(self, **kwargs):  # pylint: disable=unused-argument
        """Initialize empty map of keys."""
        self._static_keys = {}

    def _get_raw_key(self, key_id):
        """Retrieves a static, randomly generated, RSA key for the specified key id.
        :param str key_id: User-defined ID for the static key
        :returns: Wrapping key that contains the specified static key
        :rtype: :class:`aws_encryption_sdk.internal.crypto.WrappingKey`
        """
        public_key_pem = None
        with open(key_id, "rb") as key_file:
            public_key_pem = key_file.read()
            #public_key_pem = load_pem_public_key(public_key_pem, backend=default_backend())

        print(public_key_pem)
        

        escrow_encrypt_master_key = RawMasterKey(
            # The provider ID and key ID are defined by you
            # and are used by the raw RSA master key
            # to determine whether it should attempt to decrypt
            # an encrypted data key.
            provider_id="own-public",  # provider ID corresponds to key namespace for keyrings
            key_id=key_id,  # key ID corresponds to key name for keyrings
            wrapping_key=WrappingKey(
                wrapping_key=public_key_pem,
                wrapping_key_type=EncryptionKeyType.PUBLIC,
                # The wrapping algorithm tells the raw RSA master key
                # how to use your wrapping key to encrypt data keys.
                #
                # We recommend using RSA_OAEP_SHA256_MGF1.
                # You should not use RSA_PKCS1 unless you require it for backwards compatibility.
                wrapping_algorithm=WrappingAlgorithm.RSA_OAEP_SHA256_MGF1
            )
        )
        return escrow_encrypt_master_key
        return WrappingKey(
            wrapping_key=public_key_pem,
            wrapping_key_type=EncryptionKeyType.PUBLIC,
            # The wrapping algorithm tells the raw RSA master key
            # how to use your wrapping key to encrypt data keys.
            #
            # We recommend using RSA_OAEP_SHA256_MGF1.
            # You should not use RSA_PKCS1 unless you require it for backwards compatibility.
            wrapping_algorithm=WrappingAlgorithm.RSA_OAEP_SHA256_MGF1,
        )



class OwnPrivateKeyProvider(RawMasterKeyProvider):
    """Randomly generates and provides 4096-bit RSA keys consistently per unique key id."""

    provider_id = "own-public"

    def __init__(self, **kwargs):  # pylint: disable=unused-argument
        """Initialize empty map of keys."""
        self._static_keys = {}

    def _get_raw_key(self, key_id):
        """Retrieves a static, randomly generated, RSA key for the specified key id.
        :param str key_id: User-defined ID for the static key
        :returns: Wrapping key that contains the specified static key
        :rtype: :class:`aws_encryption_sdk.internal.crypto.WrappingKey`
        """
        private_key_pem = None
        with open(key_id, "rb") as key_file:
            private_key_pem = key_file.read()
            #public_key_pem = load_pem_public_key(public_key_pem, backend=default_backend())

        print(private_key_pem)

        escrow_decrypt_master_key = RawMasterKey(
                # The key namespace and key name MUST match the encrypt master key.
                provider_id="own-public",  # provider ID corresponds to key namespace for keyrings
                key_id=key_id,  # key ID corresponds to key name for keyrings
                wrapping_key=WrappingKey(
                    wrapping_key=private_key_pem,
                    wrapping_key_type=EncryptionKeyType.PRIVATE,
                    # The wrapping algorithm MUST match the encrypt master key.
                    wrapping_algorithm=WrappingAlgorithm.RSA_OAEP_SHA256_MGF1
                )
            )
        return escrow_decrypt_master_key
        return WrappingKey(
            wrapping_key=private_key_pem,
            wrapping_key_type=EncryptionKeyType.PRIVATE,
            # The wrapping algorithm tells the raw RSA master key
            # how to use your wrapping key to encrypt data keys.
            #
            # We recommend using RSA_OAEP_SHA256_MGF1.
            # You should not use RSA_PKCS1 unless you require it for backwards compatibility.
            wrapping_algorithm=WrappingAlgorithm.RSA_OAEP_SHA256_MGF1,
        )
