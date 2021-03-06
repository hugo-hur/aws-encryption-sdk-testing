import aws_encryption_sdk
from aws_encryption_sdk import CommitmentPolicy
from aws_encryption_sdk.key_providers.raw import RawMasterKey
from aws_encryption_sdk.key_providers.raw import RawMasterKeyProvider

from aws_encryption_sdk.internal.crypto.wrapping_keys import WrappingKey
from aws_encryption_sdk.identifiers import CommitmentPolicy, EncryptionKeyType, WrappingAlgorithm

import masterkeyprovider
from ownpublickeyprovider import OwnPublicKeyProvider, OwnPrivateKeyProvider


client = aws_encryption_sdk.EncryptionSDKClient(commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT)

"""
static_master_key_provider = masterkeyprovider.StaticRandomMasterKeyProvider()
static_master_key_provider.add_master_key("25343")

with open("input.txt", "rb") as plaintext, open("ciphertext_filename.bin", "wb") as ciphertext:
    with client.stream(source=plaintext, mode="e", key_provider=static_master_key_provider) as encryptor:
        for chunk in encryptor:
            ciphertext.write(chunk)

#Decrypt with static provider
with open("ciphertext_filename.bin", "rb") as ciphertext, open("out.txt", "wb") as plaintext:
    with client.stream(source=ciphertext, mode="d", key_provider=static_master_key_provider) as static_decryptor:
        for chunk in static_decryptor:
            plaintext.write(chunk)
"""
import argparse
parser = argparse.ArgumentParser()
parser.add_argument("filename_in")
parser.add_argument("filename_out")
args = parser.parse_args()



public_key_pem = None
with open("rsa_key.pub", "rb") as key_file:
    public_key_pem = key_file.read()

escrow_encrypt_master_key = RawMasterKey(
            # The provider ID and key ID are defined by you
            # and are used by the raw RSA master key
            # to determine whether it should attempt to decrypt
            # an encrypted data key.
            provider_id="own-key",  # provider ID corresponds to key namespace for keyrings
            key_id=b"key_id",  # key ID corresponds to key name for keyrings
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

#keyp = masterkeyprovider.StaticRandomMasterKeyProvider()
#keyp.add_master_key_provider(escrow_encrypt_master_key)


with open(args.filename_in, "rb") as plaintext, open(args.filename_out, "wb") as ciphertext:
    with client.stream(source=plaintext, mode="e", key_provider=escrow_encrypt_master_key) as encryptor:
        for chunk in encryptor:
            ciphertext.write(chunk)






#ciphertext, encrypt_header = client.encrypt(source="Hello world!", key_provider=escrow_encrypt_master_key)

#with open('testiulos.bin', 'wb') as f:
#    f.write(ciphertext)

