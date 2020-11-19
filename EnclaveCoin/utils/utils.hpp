#ifndef SGX_UTILS_H_
#define SGX_UTILS_H_

#include <sgx_urts.h>
#include <string>

void print_error_message(sgx_status_t ret);

/* Check error conditions for loading enclave */

#define print_error_message(ret) fprintf(stderr, "[%d] SGX error code: 0x%04x\n", __LINE__, ret)


std::string search_shared_library(const std::string &filename, const std::string &path);

#endif // SGX_UTILS_H_
