//
// Created by lx on 11/18/20.
//

#include "enclave_u.h"
#include "utils.hpp"
#include <sgx.h>
#include <sgx_uae_epid.h>
#include <sgx_ukey_exchange.h>
#include <cppcodec/base64_rfc4648.hpp>
#include <cppcodec/hex_lower.hpp>
#include <iostream>
#include <vector>

using base64 = cppcodec::base64_rfc4648;
using hex = cppcodec::hex_lower;
using std::string;
using std::vector;


#define sgx_check(status)           \
    if (status != SGX_SUCCESS) {       \
        print_error_message(status);   \
        return -status;                \
    }
#ifdef __cplusplus
extern "C" {
#endif

void ocall_puts(const char *str) {
    std::cerr << str << std::endl;
//    fputs(str, stderr);
//    fflush(stderr);
}

#ifdef __cplusplus
}
#endif


int main(int argc, char const *argv[]) {
    sgx_enclave_id_t eid;
    sgx_status_t status = SGX_SUCCESS;
    sgx_status_t ret;

    // create a enclave
    const char *enclave = argc < 2 ? "LxEnclave.signed.so" : argv[1];
    ret = sgx_create_enclave(enclave, SGX_DEBUG_FLAG, nullptr, nullptr, &eid, nullptr);
    sgx_check(ret);

#if 0
    uint32_t output;
    ret = ecall_coin_tossing(eid, &status, &output, 0, nullptr, 0, nullptr, 0, nullptr, 2);
    sgx_check(ret);
    sgx_check(status);
    std::cerr << "output = " << output << std::endl;

    return 0;
#endif

    // initialize a ra session
    sgx_ra_context_t ra_context;
    ret = enclave_ra_init_def(eid, &status, &ra_context);
    sgx_check(ret);
    sgx_check(status);

    // output msg0

    uint32_t extended_epid_group_id;
    ret = sgx_get_extended_epid_group_id(&extended_epid_group_id);
    sgx_check(ret);

    std::cout << base64::encode(reinterpret_cast<uint8_t *>(&extended_epid_group_id), 4) << std::endl;

    // output msg1

    sgx_ra_msg1_t msg1;
    ret = sgx_ra_get_msg1(ra_context, eid, sgx_ra_get_ga, &msg1);
    sgx_check(ret);

    std::cout << base64::encode(reinterpret_cast<uint8_t *>(&msg1), sizeof(sgx_ra_msg1_t)) << std::endl;

    // input msg2

    string msg2_encoded;
    std::cin >> msg2_encoded;
    vector<uint8_t> msg2 = base64::decode(msg2_encoded);

    sgx_ra_msg3_t *msg3_ptr;
    uint32_t msg3_size;

    // output msg3

    ret = sgx_ra_proc_msg2(ra_context, eid,
                           sgx_ra_proc_msg2_trusted, sgx_ra_get_msg3_trusted,
                           reinterpret_cast<const sgx_ra_msg2_t *>(msg2.data()), msg2.size(),
                           &msg3_ptr, &msg3_size);
    sgx_check(ret);

    std::cout << base64::encode(reinterpret_cast<uint8_t *>(msg3_ptr), msg3_size) << std::endl;

    // output key hash
    sgx_status_t retval;

    sgx_sha256_hash_t mk_hash;
    ret = enclave_ra_get_key_hash(eid, &retval, &status, ra_context, SGX_RA_KEY_MK, &mk_hash);
    sgx_check(ret);
    sgx_check(retval);
    sgx_check(status);
    std::cout << base64::encode(mk_hash, SGX_SHA256_HASH_SIZE) << std::endl;

    sgx_sha256_hash_t sk_hash;
    enclave_ra_get_key_hash(eid, &retval, &status, ra_context, SGX_RA_KEY_SK, &sk_hash);
    sgx_check(ret);
    sgx_check(retval);
    sgx_check(status);
    std::cout << base64::encode(sk_hash, SGX_SHA256_HASH_SIZE) << std::endl;

    // Coin Tossing

    string iv_encoded;
    std::cin >> iv_encoded;
    vector<uint8_t> iv = base64::decode(iv_encoded);

    string ciphertext_encoded;
    std::cin >> ciphertext_encoded;
    vector<uint8_t> ciphertext = base64::decode(ciphertext_encoded);

    string tag_encoded;
    std::cin >> tag_encoded;
    vector<uint8_t> tag = base64::decode(tag_encoded);

    uint32_t output = 0;
    uint32_t my_coin = 1;
    ret = ecall_coin_tossing(eid, &status, &output, ra_context,
                             iv.data(), iv.size(), ciphertext.data(), ciphertext.size(), tag.data(), my_coin);
    sgx_check(ret);
    sgx_check(status);
    std::cerr << "my_coin = " << my_coin << ", win     = " << output << std::endl;

    if (!output) {
        my_coin = 2;
        ret = ecall_coin_tossing(eid, &status, &output, ra_context,
                                 iv.data(), iv.size(), ciphertext.data(), ciphertext.size(), tag.data(), my_coin);
        sgx_check(ret);
        sgx_check(status);
        std::cerr << "my_coin = " << my_coin << ", win     = " << output << std::endl;
    }


    /* exit */
    std::cerr << "ret = sgx_destroy_enclave(eid);" << std::endl;
    ret = sgx_destroy_enclave(eid);
    sgx_check(ret);
    std::cin.get();

    return 0;
}
