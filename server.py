import socket
import sys
from binascii import unhexlify, hexlify
from base64 import b64decode, b64encode

from Crypto.Cipher import AES
from Crypto.Hash import CMAC, SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from hexdump import hexdump
import requests

# config
VERBOSE = True
SPID = unhexlify('6E5E7C36753F78EEB9506C784B6E0B87')
IAS_PRIMARY_SUBSCRIPTION_KEY = '84262f16cf944a05b7e719cd0b57f8db'
IAS_SECONDARY_SUBSCRIPTION_KEY = 'cf4adc642a0442a99fd5a0dfc957bc4d'
IAS_REPORT_SIGNING_CA_FILE = '~/ca/Intel_SGX_Attestation_RootCA.pem'


# constant
CURVE_NAME = 'prime256v1'

QUOTE_TYPE_UNLINKABLE = 0
QUOTE_TYPE_LINKABLE = 1

SERVICE_PRIVATE_KEY = int.from_bytes(
    b'\x90\xe7\x6c\xbb\x2d\x52\xa1\xce\x3b\x66\xde\x11\x43\x9c\x87\xec\x1f\x86\x6a\x3b\x65\xb6\xae\xea\xad\x57\x34\x53\xd1\x03\x8c\x01',
    'little'
)


class IntelAttestationService:
    API_BASE_URL = 'https://api.trustedservices.intel.com/sgx/dev'
    API_SIGRL = API_BASE_URL + '/attestation/v3/sigrl/{gid}'
    API_REPORT = API_BASE_URL + '/attestation/v3/report'
    HEADER_KEY_NAME = 'Ocp-Apim-Subscription-Key'

    def __init__(self, spid, primary_subscription_key, secondary_subscription_key):
        self.spid = spid
        self.primary_subscription_key = primary_subscription_key
        self.secondary_subscription_key = secondary_subscription_key

        self.session = requests.session()

    def _h(self, primary, json):
        headers = {}
        if primary:
            headers[self.HEADER_KEY_NAME] = self.primary_subscription_key
        else:
            headers[self.HEADER_KEY_NAME] = self.secondary_subscription_key

        if json:
            headers['Content-Type'] = 'application/json'

        return headers

    def _exit_handler(self, rsp, status_code, description):
        if rsp.status_code == status_code:
            request_id = rsp.headers.get('Request-ID')
            print(request_id, description)
            sys.exit(status_code)

    def retrieve_sigrl(self, epid_group_id):
        gid = int(epid_group_id).to_bytes(4, 'big')
        url = self.API_SIGRL.format(gid=hexlify(gid).decode('ascii'))

        print('retrieve_sigrl url: ', url)
        rsp = self.session.get(url, headers=self._h(True, False))
        request_id = rsp.headers.get('Request-ID')
        if VERBOSE:
            print('')
            print(rsp.request.headers)
            print(rsp.headers)

        if rsp.status_code == 401:
            print(request_id, 's: Failed to authenticate or authorize request.')
            rsp = self.session.get(url, headers=self._h(False, False))
            request_id = rsp.headers.get('Request-ID')

        self._exit_handler(
            rsp, 401, 's: Failed to authenticate or authorize request.'
        )
        self._exit_handler(
            rsp, 500, 's: Internal error occurred.'
        )
        self._exit_handler(
            rsp, 503, 's: Service is currently not able to process the request.'
        )

        if rsp.status_code == 404:
            print(
                request_id, '{gid} does not refer to a valid EPID group ID.'.format(gid=gid))
            return request_id, rsp.status_code,  None

        if rsp.status_code != 200:
            print(request_id, 's: Unexpected Error: {}'.format(rsp.status_code))
            sys.exit(rsp.status_code)

        sigrl = b64decode(rsp.content)

        return request_id, rsp.status_code,  sigrl

    def verify_attestation_evidence(self, isvEnclaveQuote, pseManifest=None, nonce=None):
        payload = {
            'isvEnclaveQuote': b64encode(isvEnclaveQuote)
        }

        if pseManifest:
            payload['pseManifest'] = b64encode(pseManifest)

        if nonce:
            payload['nonce'] = nonce

        rsp = self.session.get(self.API_REPORT, headers=self._h(True, True))
        request_id = rsp.headers.get('Request-ID')
        if VERBOSE:
            print('')
            print(rsp.request.headers)
            print(rsp.headers)

        if rsp.status_code == 401:
            print(request_id, 'Failed to authenticate or authorize request.')
            rsp = self.session.get(
                self.API_REPORT, headers=self._h(False, True))
            request_id = rsp.headers.get('Request-ID')

        self._exit_handler(
            rsp, 400, 'v: Invalid Attestation Evidence Payload.'
        )
        self._exit_handler(
            rsp, 401, 'v: Failed to authenticate or authorize request.'
        )
        self._exit_handler(
            rsp, 500, 'v: Internal error occurred.'
        )
        self._exit_handler(
            rsp, 503, 'v: Service is currently not able to process the request.'
        )

        if rsp.status_code != 200:
            print(request_id, 'v: Unexpected Error: {}'.format(rsp.status_code))
            sys.exit(rsp.status_code)

        report_signature = b64decode(rsp.headers['X-IASReport-Signature'])
        cert_chain = rsp.headers['X-IASReport-Signing-Certificate']
        advisory_url = rsp.headers.get('Advisory-URL')
        advisory_ids = rsp.headers.get('Advisory-IDs')

        return (request_id, report_signature, cert_chain, advisory_url, advisory_ids), rsp.json()


def get_socket_server(host, port, max_conn=2):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen(max_conn)

    print("Server listening on {}:{}".format(host, port))

    return server


def generate_seed(literal):
    return b''.join([b'\x01', literal.encode('ascii'), b'\x00\x80\x00'])


def recv_bytes(client, size):
    data = client.recv(size*2)

    if VERBOSE:
        print('')
        hexdump(data)

    return unhexlify(data)


def parse_int(bytes, endian='little'):
    return int.from_bytes(bytes, endian)


def recv_msg0(client):
    extended_epid_group_id = parse_int(recv_bytes(client, 4))
    return extended_epid_group_id


def recv_msg1(client):
    Gax = parse_int(recv_bytes(client, 32))
    Gay = parse_int(recv_bytes(client, 32))
    epid_group_id = parse_int(recv_bytes(client, 4))

    Ga = ECC.construct(curve=CURVE_NAME, point_x=Gax, point_y=Gay)
    return Ga, epid_group_id


def multiply(a, G):
    base = G
    result = G.point_at_infinity()

    while a > 1:
        if a & 1 == 1:
            result += base

        a = a >> 1
        base = base.double()

    if a == 1:
        result += base

    return result


def derive_shared_key(Ga_point: ECC.EccPoint, Gb_k):
    # shared_secret = (Gb_k*Ga_point).point_x.to_bytes(32, 'little')
    shared_point = multiply(Gb_k, Ga_point)
    shared_secret = int(shared_point.x).to_bytes(32, 'little')
    cmac_key = b'\x00'*16
    kdk = CMAC.new(cmac_key, msg=shared_secret, ciphermod=AES).digest()
    smk = CMAC.new(kdk, msg=generate_seed('SMK'), ciphermod=AES).digest()

    return kdk, smk


def ec_point_serialize(point: ECC.EccPoint):
    return b''.join(int(n).to_bytes(32, 'little') for n in point.xy)


def send_msg2(client, epid_group_id, Ga_point, Gb, smk):
    # serialize Ga, Gb
    Ga_ser = ec_point_serialize(Ga_point)
    Gb_ser = ec_point_serialize(Gb.pointQ)

    # build A
    # msg = Gb_ser
    # msg += SPID
    Quote_Type = int(QUOTE_TYPE_UNLINKABLE).to_bytes(2, 'little')  # Quote_Type
    KDF_ID = int(1).to_bytes(2, 'little')  # KDF_ID

    service_key = ECC.construct(curve=CURVE_NAME, d=SERVICE_PRIVATE_KEY)
    msg_hash = SHA256.new(Gb_ser+Ga_ser)

    print('SHA256(Gb_ser || Ga_ser)')
    hexdump(msg_hash.digest())

    SigSP = DSS.new(service_key, 'fips-186-3').sign(msg_hash)
    sig_r = int.from_bytes(SigSP[:32], 'big').to_bytes(32, 'little')
    sig_s = int.from_bytes(SigSP[32:], 'big').to_bytes(32, 'little')
    SigSP = b''.join([sig_r, sig_s])

    msg = b''.join([Gb_ser, SPID, Quote_Type, KDF_ID, SigSP])
    assert(len(msg) == 32 + 32 + 16 + 2 + 2 + 32 + 32)

    # calculate cmac_smk(A)
    mac = CMAC.new(smk, msg=msg, ciphermod=AES).digest()

    # retrieve sigrl
    request_id, status_code, sigrl_data = ias.retrieve_sigrl(epid_group_id)
    if status_code != 200:
        # TODO: Do something more friendly
        print(request_id, 'Invalid EPID Group')
        sys.exit(-1)

    sigrl_size = int(len(sigrl_data)).to_bytes(4, 'little')

    # send msg1
    data = hexlify(msg + mac + sigrl_size + sigrl_data)
    if VERBOSE:
        print('>>> Gb_ser')
        hexdump(Gb_ser)
        print('>>> SPID')
        hexdump(SPID)
        print('>>> Quote_Type')
        hexdump(Quote_Type)
        print('>>> KDF_ID')
        hexdump(KDF_ID)
        print('>>> SigSP')
        hexdump(SigSP)
        print('>>> CMAC_SMK(A)')
        hexdump(mac)
        print('>>> sigrl_size')
        hexdump(sigrl_size)
        print('>>> sigrl_data')
        hexdump(sigrl_data)

    client.send(data)
    client.send(b'\n')


def recv_msg3_verify(client, Ga_point: ECC.EccPoint, Gb_point: ECC.EccPoint, smk, kdk):
    Ga_ser = ec_point_serialize(Ga_point)
    Gb_ser = ec_point_serialize(Gb_point)

    # receive
    mac = recv_bytes(client, 16)

    M = recv_bytes(client, 32+32+256+436)
    signature_len = parse_int(M[-4:])
    M += recv_bytes(client, signature_len)

    # verification
    if Ga_ser != M[:64]:
        return False, "Step1: Peer PK doesn't match to the previous one"

    try:
        CMAC.new(smk, msg=M, ciphermod=AES).verify(mac)
    except ValueError:
        return False, "Step2: Invalid MAC"

    quote = M[32+32+256:]
    report_body = quote[48:432]

    header = report_body[:32]
    keyhash = SHA256.new(b''.join([Ga_ser, Gb_ser, generate_seed('VK')]))

    if header != keyhash.digest():
        return False, "Step3: Key Hash doesn't match"

    if VERBOSE:
        hexdump(quote)

    return True, quote


def main(client, ias):
    # proc msg0
    extended_epid_group_id = recv_msg0(client)
    print('extended_epid_group_id: ', extended_epid_group_id)

    # proc msg1
    Ga, epid_group_id = recv_msg1(client)
    print('')
    print('Ga: ', Ga)
    print('epid_group_id: ', epid_group_id)

    # calc kdk, smk
    Gb = ECC.generate(curve=CURVE_NAME)
    print('Gb: ', Gb)
    kdk, smk = derive_shared_key(Ga.pointQ, Gb.d)

    # send msg2
    send_msg2(client, epid_group_id, Ga.pointQ, Gb, smk)
    print('Msg2 Sent')

    # recv msg3
    verif, payload = recv_msg3_verify(client, Ga.pointQ, Gb.pointQ, smk, kdk)
    if not verif:
        print('Fail to verify Msg3', payload)
        sys.exit(-1)

    meta, rsp = ias.verify_attestation_evidence(payload)
    (request_id, report_signature, cert_chain, advisory_url, advisory_ids) = meta

    # FIXME: Validate the signing certificate received in the report response.
    # FIXME: Validate the report signature using the signing certificate.

    # If the quote is successfully validated in Step 3, perform the following:
    #     Extract the attestation status for the enclave and, if provided, the PSE.
    #     Examine the enclave identity (MRSIGNER), security version and product ID.
    #     Examine the debug attribute and ensure it is not set (in a production environment).
    #     Decide whether or not to trust the enclave and, if provided, the PSE.

    MK = CMAC.new(kdk, msg=generate_seed('MK'), ciphermod=AES).digest()
    SK = CMAC.new(kdk, msg=generate_seed('SK'), ciphermod=AES).digest()

    # Send msg4


if __name__ == "__main__":
    server = get_socket_server('localhost', 7777)
    ias = IntelAttestationService(
        SPID,
        IAS_PRIMARY_SUBSCRIPTION_KEY,
        IAS_SECONDARY_SUBSCRIPTION_KEY
    )

    while True:
        client, addr = server.accept()
        print("Client conncet: {}".format(addr))

        main(client, ias)
