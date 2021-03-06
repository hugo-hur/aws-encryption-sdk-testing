import aws_encryption_sdk
from aws_encryption_sdk import CommitmentPolicy
from aws_encryption_sdk.key_providers.raw import RawMasterKey
from aws_encryption_sdk.key_providers.raw import RawMasterKeyProvider

from aws_encryption_sdk.internal.crypto.wrapping_keys import WrappingKey
from aws_encryption_sdk.identifiers import CommitmentPolicy, EncryptionKeyType, WrappingAlgorithm

import masterkeyprovider


client = aws_encryption_sdk.EncryptionSDKClient(commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT)


private_key_pem = None
with open("rsa_key", "rb") as key_file:
    private_key_pem = key_file.read()
escrow_decrypt_master_key = RawMasterKey(
    # The key namespace and key name MUST match the encrypt master key.
    provider_id="own-key",  # provider ID corresponds to key namespace for keyrings
    key_id=b"key_id",  # key ID corresponds to key name for keyrings
    wrapping_key=WrappingKey(
        wrapping_key=private_key_pem,
        wrapping_key_type=EncryptionKeyType.PRIVATE,
        # The wrapping algorithm MUST match the encrypt master key.
        wrapping_algorithm=WrappingAlgorithm.RSA_OAEP_SHA256_MGF1,
    ),
)

keyp = masterkeyprovider.StaticRandomMasterKeyProvider()
keyp.add_master_key_provider(escrow_decrypt_master_key)





#Decrypt with static provider
with open("ciphertext_filename.bin", "rb") as ciphertext, open("out.txt", "wb") as plaintext:
    with client.stream(source=ciphertext, mode="d", key_provider=keyp) as static_decryptor:
        for chunk in static_decryptor:
            plaintext.write(chunk)