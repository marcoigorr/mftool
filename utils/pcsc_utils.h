/**
 * @file pcsc_utils.h
 * @brief Funzioni di utilità per la gestione degli errori PC/SC (WinSCard API).
 *
 * Copyright (C) 2026 Marco Petronio
 *
 * This file is part of mftool.
 *
 * mftool is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * mftool is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with mftool. If not, see <https://www.gnu.org/licenses/>.
 */
#pragma once
#include <winscard.h>
#include <string>

/**
 * @brief Converte un codice di errore PC/SC in una stringa leggibile.
 *
 * @param status Codice di stato restituito da una funzione WinSCard (LONG).
 * @return Stringa descrittiva dell'errore corrispondente al codice di stato.
 */
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
    case SCARD_E_NOT_READY: return "Reader not ready";
    case SCARD_E_NO_SERVICE: return "Smart card service not running";
    case SCARD_W_UNRESPONSIVE_CARD: return "Card unresponsive (needs reset)";
    case SCARD_W_UNPOWERED_CARD: return "Card not powered";
    case SCARD_W_RESET_CARD: return "Card was reset";
    case SCARD_W_REMOVED_CARD: return "Card removed";
    default: return "Unknown error: " + std::to_string(status);
    }
}