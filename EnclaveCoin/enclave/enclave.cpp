//
// Created by lx on 11/18/20.
//

#include <sgx.h>
#include <sgx_tkey_exchange.h>
#include <tlibc/string.h>
#include "peer_public.h"
#include "enclave_t.h"
#include <cstdio>
#include <tlibc/mbusafecrt.h>
#include <cppcodec/hex_lower.hpp>

using hex = cppcodec::hex_lower;

char buffer[BUFSIZ];

sgx_status_t printf(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    _vsprintf_s(buffer, BUFSIZ, fmt, ap);
            va_end(ap);

    return ocall_puts(buffer);
}


sgx_status_t enclave_ra_init_def(sgx_ra_context_t *ctx) {
    return sgx_ra_init(&peer_public_default, 0, ctx);
}

sgx_status_t enclave_ra_close(sgx_ra_context_t ctx) {
    return sgx_ra_close(ctx);
}

sgx_status_t enclave_ra_get_key_hash(sgx_status_t *get_keys_ret,
                                     sgx_ra_context_t ctx, sgx_ra_key_type_t type, sgx_sha256_hash_t *hash) {
    sgx_status_t sha_ret;
    sgx_ra_key_128_t k;

    // First get the requested key which is one of:
    //  * SGX_RA_KEY_MK
    //  * SGX_RA_KEY_SK
    // per sgx_ra_get_keys().

    *get_keys_ret = sgx_ra_get_keys(ctx, type, &k);
    if (*get_keys_ret != SGX_SUCCESS) return *get_keys_ret;

    /* Now generate a SHA hash */
    sha_ret = sgx_sha256_msg((const uint8_t *) &k, sizeof(k),
                             (sgx_sha256_hash_t *) hash); // Sigh.

    /* Let's be thorough */
    memset(k, 0, sizeof(k));

    return sha_ret;
}

sgx_status_t ecall_coin_tossing(uint32_t *output, sgx_ra_context_t ctx,
                                uint8_t *iv, uint32_t iv_len,
                                uint8_t *ct, uint32_t ct_len,
                                uint8_t tag[16], uint32_t coin) {

    sgx_status_t status;
    sgx_ra_key_128_t key;
    uint32_t peer_coin;

    status = sgx_ra_get_keys(ctx, SGX_RA_KEY_SK, &key);
    if (status != SGX_SUCCESS) return status;

    sgx_aes_gcm_128bit_tag_t in_mac;
    memcpy_s(in_mac, SGX_AESGCM_MAC_SIZE, tag, 16);

    status = sgx_rijndael128GCM_decrypt(reinterpret_cast<const sgx_aes_gcm_128bit_key_t *>(&key),
                                        ct, ct_len, reinterpret_cast<uint8_t *>(&peer_coin),
                                        iv, iv_len, nullptr, 0,
                                        &in_mac);
    if (status != SGX_SUCCESS) return status;
    *output = ((peer_coin ^ coin) % 2 == 0);

    return status;
}
