import json
from enum import Enum
from io import BytesIO
from typing import Tuple

from Cryptodome.Cipher import AES
from Cryptodome.Hash import CMAC, SHA256
from Cryptodome.Hash.SHA256 import SHA256Hash
from Cryptodome.PublicKey import ECC
from Cryptodome.PublicKey.ECC import EccKey
from Cryptodome.Signature import DSS
from Cryptodome.Signature.DSS import FipsEcDsaSigScheme
from hexdump import hexdump

from sgx_ias import IntelAttestationService

__all__ = ['RemoteAttestation']

# integer searialization and deserialization
VERBOSE = False


def _load_int(raw: bytes, byteorder='little') -> int:
    return int.from_bytes(raw, byteorder)


def _dump_int(value: int, len: int, byteorder='little') -> bytes:
    return int(value).to_bytes(len, byteorder)

# aes cmac and crypto


def _aes_cmac(key: bytes, msg: bytes) -> bytes:
    return CMAC.new(key, msg, ciphermod=AES).digest()


def _sha256(*args) -> SHA256Hash:
    sha = SHA256.new()

    for arg in args:
        sha.update(arg)

    return sha


def _ecdsa(private_key: EccKey, *args) -> FipsEcDsaSigScheme:
    return DSS.new(private_key, 'fips-186-3').sign(_sha256(*args))


def _serialize_ec_point(point: ECC.EccPoint):
    return b''.join(int(n).to_bytes(32, 'little') for n in point.xy)

# sgx specific


def _generate_seed(literal):
    return b''.join([b'\x01', literal.encode('ascii'), b'\x00\x80\x00'])


class QuoteType(Enum):
    UNLINKABLE = _dump_int(0, 2)
    LINKABLE = _dump_int(1, 2)


class RemoteAttestation:
    CURVE_NAME = 'prime256v1'
    KDF_ID = _dump_int(1, 2)

    SEED_SMK = _generate_seed('SMK')
    SEED_VK = _generate_seed('VK')
    SEED_MK = _generate_seed('MK')
    SEED_SK = _generate_seed('SK')

    ias = IntelAttestationService
    quote_type: QuoteType
    sim = bool

    service_key: EccKey
    extended_epid_group_id: int
    Ga: EccKey = None  # remote key (public only)
    Gb: EccKey = None  # local key

    def __init__(self, service_key: EccKey, quote_type: QuoteType, ias: IntelAttestationService, sim=True):
        self.service_key = service_key
        self.quote_type = quote_type
        self.ias = ias
        self.sim = sim

    def receive_msg1(self, msg: bytes):
        io = BytesIO(msg)
        Gax = io.read(32)
        Gay = io.read(32)
        gid = io.read(4)

        self.Ga = ECC.construct(
            curve=self.CURVE_NAME,
            point_x=_load_int(Gax),
            point_y=_load_int(Gay)
        )

        self.epid_group_id = _load_int(gid)
        self._handle_msg1_msg2()

    def _handle_msg1_msg2(self):
        # Generate local key pair
        self.Gb = ECC.generate(curve=self.CURVE_NAME)

        # derive_shared_key
        shared_point = self.Ga.pointQ * self.Gb.d
        shared_secret = _dump_int(shared_point.x, 32)

        cmac_key = b'\x00' * 16
        self.kdk = _aes_cmac(key=cmac_key, msg=shared_secret)
        self.smk = _aes_cmac(key=self.kdk, msg=self.SEED_SMK)

    def generate_msg2(self) -> bytes:
        # serialize Ga, Gb
        Ga_ser = _serialize_ec_point(self.Ga.pointQ)
        Gb_ser = _serialize_ec_point(self.Gb.pointQ)

        # build A
        sig_sp = _ecdsa(self.service_key, Gb_ser, Ga_ser)
        sig_sp = b''.join([
            _dump_int(_load_int(x, 'big'), 32)
            for x in [sig_sp[:32], sig_sp[32:]]
        ])

        msg = Gb_ser + self.ias.spid + self.quote_type.value + self.KDF_ID + sig_sp
        assert(len(msg) == (32 + 32) + 16 + 2 + 2 + 32 + 32)

        # calculate cmac_smk(A)
        mac = _aes_cmac(key=self.smk, msg=msg)

        # retrieve sigrl
        if self.sim:
            sigrl = b''
        else:
            request_id, status, sigrl = self.ias.retrieve_sigrl(self.epid_group_id)
            if status != 200:
                # TODO: Do something more friendly
                print(request_id, 'Invalid EPID Group')
                return None

        sigrl_size = _dump_int(len(sigrl), 4)

        return msg + mac + sigrl_size + sigrl

    def recv_msg3_verify(self, msg3: bytes) -> Tuple[dict, str]:
        pre_quote_len = 16 + 32 + 32 + 256

        io = BytesIO(msg3)

        mac = io.read(16)
        g_a = io.read(32 + 32)

        ps_sec_prop = io.read(256)
        version = io.read(2)
        sign_type = io.read(2)
        epid_group_id = io.read(4)
        qe_svn = io.read(2)
        pce_svn = io.read(2)
        xeid = io.read(4)
        basename = io.read(32)

        cpu_svn = io.read(16)           # Security Version of the CPU
        misc_select = io.read(4)        # Which fields defined in SSA.MISC
        _ = io.read(12)                 #
        isv_ext_prod_id = io.read(16)   # ISV assigned Extended Product ID
        attributes = io.read(16)        # Any special Capabilities the Enclave possess
        mr_enclave = io.read(32)        # The value of the enclave's ENCLAVE measurement
        _ = io.read(32)                 #
        mr_signer = io.read(32)         # The value of the enclave's SIGNER measurement
        _ = io.read(32)                 #
        config_id = io.read(64)         # CONFIGID
        isv_prod_id = io.read(2)        # Product ID of the Enclave
        isv_svn = io.read(2)            # Security Version of the Enclave
        config_svn = io.read(2)         # CONFIGSVN
        reserved4 = io.read(42)         #
        isv_family_id = io.read(16)     # ISV assigned Family ID
        report_data = io.read(64)       # Data provided by the user

        signature_len = _load_int(io.read(4))
        signature = io.read(signature_len)

        # Verify that Ga in msg3 matches Ga in msg1.

        Ga_ser = _serialize_ec_point(self.Ga.pointQ)
        Gb_ser = _serialize_ec_point(self.Gb.pointQ)

        if Ga_ser != g_a:
            return None, "Step1: Peer PK doesn't match to the previous one"

        # Verify CMAC_SMK(M).

        m = msg3[16:pre_quote_len + 436 + signature_len]
        try:
            CMAC.new(self.smk, msg=m, ciphermod=AES).verify(mac)
        except ValueError:
            return None, "Step2: Invalid MAC"

        # Verify that the first 32-bytes of the report data match the SHA-256
        # digest of (Ga || Gb || VK), where || denotes concatenation.
        # VK is derived by performing an AES-128 CMAC over the following byte
        # sequence, using the KDK as the key:
        # 0x01 || "VK" || 0x00 || 0x80 || 0x00

        vk = _aes_cmac(key=self.kdk, msg=self.SEED_VK)
        keyhash = _sha256(Ga_ser, Gb_ser, vk).digest()

        if report_data[:32] != keyhash:
            if VERBOSE:
                print('>>> First 32-bytes of the report data')
                hexdump(report_data[:32])
                print('>>> SHA256(Ga||Gb||VK)')
                hexdump(keyhash)

            return None, "Step3: Key Hash doesn't match"

        if self.sim:
            attestation_report = {}
            advisory_url = ''
        else:

            # Verify the attestation evidence provided by the client.
            # 1. Extract the quote from msg3.
            quote = msg3[pre_quote_len:pre_quote_len + 436 + signature_len]

            if VERBOSE:
                print('>>> quote')
                hexdump(quote)

            # 2. Submit the quote to IAS, calling the API function to verify attestation evidence.
            request_id, report_signature, cert_chain, advisory_url, _, response = self.ias.verify_attestation_evidence(quote)
            # TODO: 3. Validate the signing certificate received in the report response.
            # TODO: 4. Validate the report signature using the signing certificate.

            # If the quote is successfully validated in Step 3, perform the following:
            # 1. Extract the attestation status for the enclave and, if provided, the PSE.
            attestation_report = json.loads(response)
            # TODO: 2. Examine the enclave identity (MRSIGNER), security version and product ID.
            # TODO: 3. Examine the debug attribute and ensure it is not set (in a production environment).
            # TODO: 4. Decide whether or not to trust the enclave and, if provided, the PSE.

            # Derive the session keys, SK and MK, that should be used to transmit
            # future messages between the client and server during the session.
            # The client can simply call sgx_ra_get_keys(), but the server must
            # derive them manually by performing an AES-128 CMAC over the following
            # byte sequences, using the KDK as the key:
            # MK: 0x01 || "MK" || 0x00 || 0x80 || 0x00
            # SK: 0x01 || "SK" || 0x00 || 0x80 || 0x00

        self.mk = _aes_cmac(key=self.kdk, msg=self.SEED_MK)
        self.sk = _aes_cmac(key=self.kdk, msg=self.SEED_SK)

        # Generate msg4 and send it to the client.

        return attestation_report, advisory_url
