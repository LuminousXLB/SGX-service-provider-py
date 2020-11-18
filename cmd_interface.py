from base64 import b64decode, b64encode
from binascii import hexlify
from pathlib import Path
from subprocess import PIPE, Popen

from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import ECC
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


BUILD_PATH = Path('/home/lx/CLionProjects/EnclaveCoin/cmake-build-debug/')
EXECUTABLE = BUILD_PATH / 'LxApp'
SIGNED_ENCLAVE = BUILD_PATH / 'LxEnclave.signed.so'


class InteractiveEnclave:
    _p: Popen

    def __init__(self, elf: Path, signed_enclave: Path) -> None:
        assert(elf.exists())
        assert(signed_enclave.exists())

        self._p = Popen([elf, str(signed_enclave.absolute())], stdin=PIPE, stdout=PIPE)

    def _write(self, data: bytes) -> None:
        self._p.stdin.write(data)
        self._p.stdin.flush()

    def writeline(self, message: bytes) -> None:
        data = b64encode(message)
        self._write(data + b'\n')

    def read(self) -> bytes:
        raw = self._p.stdout.readline().strip()
        msg = b64decode(raw)

        return msg


if __name__ == "__main__":

    proc = InteractiveEnclave(EXECUTABLE, SIGNED_ENCLAVE)
    ra = RemoteAttestation(
        SERVICE_KEY,
        QuoteType.UNLINKABLE,
        IntelAttestationService(SPID, IAS_PRIMARY_SUBSCRIPTION_KEY, IAS_SECONDARY_SUBSCRIPTION_KEY)
    )

    # Receive Msg0

    msg0 = proc.read()
    logger.debug(f'msg0 <- {hexlify(msg0)}')

    extended_epid_group_id = int.from_bytes(msg0, 'little')
    print(extended_epid_group_id)

    # Receive Msg1

    msg1 = proc.read()
    logger.debug(f'msg1 <- {hexlify(msg1)}')
    ra.receive_msg1(msg1)

    # Send Msg2

    msg2 = ra.generate_msg2()
    logger.debug(f'msg2 -> {hexlify(msg1)}')
    proc.writeline(msg2)

    # Receive Msg3
    msg3 = proc.read()
    logger.debug(f'msg3 <- {hexlify(msg3)}')
    report, advisory = ra.recv_msg3_verify(msg3)

    # mk and sk
    logger.debug(f'MK = {hexlify(SHA256.new(ra.mk).digest())}')
    logger.debug(f'SK = {hexlify(SHA256.new(ra.sk).digest())}')
