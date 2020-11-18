import sys
import json
from base64 import b64encode
from binascii import hexlify
from pathlib import Path

from Cryptodome.Cipher import AES
from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import ECC
from Cryptodome.Random import get_random_bytes
from hexdump import hexdump
from loguru import logger

from private import *
from sgx_ias import IntelAttestationService
from sgx_ra import QuoteType, RemoteAttestation

SERVICE_PRIVATE_KEY = int.from_bytes(
    unhexlify('90e76cbb2d52a1ce3b66de11439c87ec1f866a3b65b6aeeaad573453d1038c01'),
    'little'
)
SERVICE_KEY = ECC.construct(
    curve=RemoteAttestation.CURVE_NAME, d=SERVICE_PRIVATE_KEY)


if __name__ == "__main__":
    import zerorpc

    c = zerorpc.Client()
    c.connect("tcp://127.0.0.1:4242")

    # Remote Attestation

    ra = RemoteAttestation(
        SERVICE_KEY,
        QuoteType.UNLINKABLE,
        IntelAttestationService(SPID, IAS_PRIMARY_SUBSCRIPTION_KEY, IAS_SECONDARY_SUBSCRIPTION_KEY)
    )

    msg0, msg1 = c.remote_attestation_init()

    logger.debug(f'msg0 <- {hexlify(msg0)}')
    logger.debug(f'msg1 <- {hexlify(msg1)}')

    msg2 = ra.receive_msg1(msg1)
    logger.debug(f'msg2 -> {hexlify(msg1)}')

    msg3, mk_hash, sk_hash = c.remote_attestation_update(msg2)
    logger.debug(f'msg3 <- {hexlify(msg3)}')

    report, advisory = ra.recv_msg3_verify(msg3)

    v_mk = mk_hash == SHA256.new(ra.mk).digest()
    v_sk = sk_hash == SHA256.new(ra.sk).digest()
    if v_mk and v_sk:
        logger.info(f'SHA256(MK) = {hexlify(mk_hash)}')
        logger.info(f'SHA256(SK) = {hexlify(sk_hash)}')
    else:
        raise Exception("Remote Attestation Failed")

    # Coin tossing

    # coin = int.from_bytes(get_random_bytes(4), 'little')
    coin = 0x123456
    # iv = unhexlify('5016e1d232e7d0f01e15ce610356054c')
    # key = unhexlify('beb4b02dbce8708c1c0d030f40909b61') # ra.sk
    key = ra.sk

    cipher = AES.new(key, AES.MODE_GCM, nonce=get_random_bytes(12))
    ciphertext, tag = cipher.encrypt_and_digest(int.to_bytes(coin, 4, 'little'))
    iv = cipher.nonce

    print(f'key =           {hexlify(key)}')
    print(f'iv =            {hexlify(iv)}')
    print(f'ciphertext =    {hexlify(ciphertext)}')
    print(f'tag =           {hexlify(tag)}')
    c.coin_tossing(iv, ciphertext, tag)
