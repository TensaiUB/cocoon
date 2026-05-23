#pragma once

#include "td/utils/format.h"
#include "td/utils/Status.h"
#include <sgx_error.h>
#include <sgx_ql_lib_common.h>

// Helper macros to reduce boilerplate around SGX/DCAP/TEE error checking.
// They create a detailed td::Status on failure, including the failing code,
// file and line, and allow the caller to simply `return` it.

#define SGX_CHECK_OK(expr, message)                                                                                   \
  do {                                                                                                                \
    sgx_status_t _sgx_res = (expr);                                                                                   \
    if (_sgx_res != SGX_SUCCESS) {                                                                                    \
      return ::td::Status::Error(PSTRING() << (message) << " : 0x" << ::td::format::as_hex(_sgx_res) << " (" << #expr \
                                           << ") at " << __FILE__ << ":" << __LINE__);                                \
    }                                                                                                                 \
  } while (0)

#define TEE_CHECK_OK(expr, message)                                                                                   \
  do {                                                                                                                \
    auto _tee_res = (expr);                                                                                           \
    if (_tee_res != TEE_SUCCESS) {                                                                                    \
      return ::td::Status::Error(PSTRING() << (message) << " : 0x" << ::td::format::as_hex(_tee_res) << " (" << #expr \
                                           << ") at " << __FILE__ << ":" << __LINE__);                                \
    }                                                                                                                 \
  } while (0)

// DCAP Quote Library (quote3) error checker. sgx_qe_* APIs return quote3_error_t
// where SGX_QL_SUCCESS (0) indicates success.
#define QL_CHECK_OK(expr, message)                                                                                   \
  do {                                                                                                               \
    quote3_error_t _ql_res = (expr);                                                                                 \
    if (_ql_res != SGX_QL_SUCCESS) {                                                                                 \
      return ::td::Status::Error(PSTRING() << (message) << " : 0x" << ::td::format::as_hex(_ql_res) << " (" << #expr \
                                           << ") at " << __FILE__ << ":" << __LINE__);                               \
    }                                                                                                                \
  } while (0)
