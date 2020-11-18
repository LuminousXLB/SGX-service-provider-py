from base64 import b64decode, b64encode
from binascii import hexlify
from pathlib import Path
from subprocess import PIPE, Popen

from loguru import logger

from private import *


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


class EnclaveRPC:

    proc = InteractiveEnclave(EXECUTABLE, SIGNED_ENCLAVE)

    def remote_attestation_init(self):
        msg0 = self.proc.read()
        msg1 = self.proc.read()

        return msg0, msg1

    def remote_attestation_update(self, msg2):
        self.proc.writeline(msg2)

        msg3 = self.proc.read()
        mk_hash = self.proc.read()
        sk_hash = self.proc.read()

        logger.info(f'SHA256(MK) = {hexlify(mk_hash)}')
        logger.info(f'SHA256(SK) = {hexlify(sk_hash)}')

        return msg3, mk_hash, sk_hash

    def coin_tossing(self, iv, ciphertext, tag):
        self.proc.writeline(iv)
        self.proc.writeline(ciphertext)
        self.proc.writeline(tag)
        


if __name__ == "__main__":
    import zerorpc
    s = zerorpc.Server(EnclaveRPC())
    s.bind("tcp://0.0.0.0:4242")
    s.run()
