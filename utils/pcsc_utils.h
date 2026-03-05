#pragma once
#include <winscard.h>
#include <string>

inline std::string stringifyError(LONG status) {
    switch (status) {
    case SCARD_S_SUCCESS: return "Success";
    case SCARD_E_INVALID_HANDLE: return "Invalid handle";
    case SCARD_E_INVALID_PARAMETER: return "Invalid parameter";
    case SCARD_E_NO_SMARTCARD: return "No smart card";
    case SCARD_E_UNKNOWN_READER: return "Unknown reader";
    case SCARD_E_TIMEOUT: return "Timeout";
    case SCARD_E_SHARING_VIOLATION: return "Sharing violation";
    case SCARD_E_PROTO_MISMATCH: return "Protocol mismatch";
    default: return "Unknown error: " + std::to_string(status);
    }
}