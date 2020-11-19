import sys
from base64 import b64decode, b64encode
from binascii import hexlify
from urllib.parse import unquote

import requests

VERBOSE = True


def pretty_print_dict(banner, obj):
    import json
    print(banner, json.dumps(dict(**obj), indent=2))


class IASException(Exception):
    def __init__(self, request_id) -> None:
        self.request_id = request_id

    def __str__(self) -> str:
        return f'{self.request_id}'


class Invalid_EPID_Group(IASException):
    def __init__(self, request_id, epid_group_id) -> None:
        IASException.__init__(self, request_id)
        self.epid_group_id = epid_group_id

    def __str__(self) -> str:
        return f'{self.request_id}: {self.epid_group_id} does not refer to a valid EPID group ID.'


class IntelAttestationService:
    API_BASE_URL = 'https://api.trustedservices.intel.com/sgx/dev'
    API_SIGRL = API_BASE_URL + '/attestation/v4/sigrl/{gid}'
    API_REPORT = API_BASE_URL + '/attestation/v4/report'
    HEADER_KEY_NAME = 'Ocp-Apim-Subscription-Key'

    def __init__(self, spid: bytes, primary_subscription_key: str, secondary_subscription_key: str):
        self.spid = spid
        self.primary_subscription_key = primary_subscription_key
        self.secondary_subscription_key = secondary_subscription_key

        self.session = requests.session()

    def _h(self, primary: bool, json: bool):
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

    def _handle_401_500_503(self, rsp, banner):
        self._exit_handler(
            rsp, 401, '{}: Failed to authenticate or authorize request.'.format(
                banner)
        )
        self._exit_handler(
            rsp, 500, '{}: Internal error occurred.'.format(banner)
        )
        self._exit_handler(
            rsp, 503, '{}: Service is currently not able to process the request.'.format(
                banner)
        )

    def retrieve_sigrl(self, epid_group_id: int):
        gid = int(epid_group_id).to_bytes(4, 'big')
        url = self.API_SIGRL.format(gid=hexlify(gid).decode('ascii'))

        print('retrieve_sigrl url: ', url)
        rsp = self.session.get(url, headers=self._h(True, False))
        request_id = rsp.headers.get('Request-ID')
        if VERBOSE:
            print('')
            pretty_print_dict('request.headers', rsp.request.headers)
            pretty_print_dict('response.headers', rsp.headers)

        if rsp.status_code == 401:
            print(request_id, 's: Failed to authenticate or authorize request.')
            rsp = self.session.get(url, headers=self._h(False, False))
            request_id = rsp.headers.get('Request-ID')

        self._handle_401_500_503(rsp, 's')

        if rsp.status_code == 404:
            raise Invalid_EPID_Group(epid_group_id, request_id)

        if rsp.status_code != 200:
            print(request_id, 's: Unexpected Error: {}'.format(rsp.status_code))
            sys.exit(rsp.status_code)

        sigrl = b64decode(rsp.content)

        return request_id, rsp.status_code, sigrl

    def verify_attestation_evidence(self, isvEnclaveQuote: bytes, pseManifest=None, nonce=None):
        payload = {
            'isvEnclaveQuote': b64encode(isvEnclaveQuote).decode()
        }

        if pseManifest:
            payload['pseManifest'] = b64encode(pseManifest).decode()

        if nonce:
            payload['nonce'] = nonce

        rsp = self.session.post(
            self.API_REPORT, json=payload, headers=self._h(True, True))
        request_id = rsp.headers.get('Request-ID')
        if VERBOSE:
            print('')
            pretty_print_dict('request.headers', rsp.request.headers)
            pretty_print_dict('response.headers', rsp.headers)

        if rsp.status_code == 401:
            print(request_id, 'Failed to authenticate or authorize request.')
            rsp = self.session.get(
                self.API_REPORT, headers=self._h(False, True))
            request_id = rsp.headers.get('Request-ID')

        self._exit_handler(
            rsp, 400, 'v: Invalid Attestation Evidence Payload.'
        )

        self._handle_401_500_503(rsp, 'v')

        if rsp.status_code != 200:
            print(request_id, 'v: Unexpected Error: {}'.format(rsp.status_code))
            sys.exit(rsp.status_code)

        report_signature = b64decode(rsp.headers['X-IASReport-Signature'])
        cert_chain = unquote(rsp.headers['X-IASReport-Signing-Certificate'])
        advisory_url = rsp.headers.get('Advisory-URL')
        advisory_ids = rsp.headers.get('Advisory-IDs')

        return request_id, report_signature, cert_chain, advisory_url, advisory_ids, rsp.content
