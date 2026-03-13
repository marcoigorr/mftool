/**
 * @file pcsc_reader.cpp
 * @brief Implementazione del wrapper PC/SC per la comunicazione con lettori e carte NFC.
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
#include "pcsc_reader.h"
#include "../utils/logger.h"
#include "../utils/hex.h"
#include "../utils/pcsc_utils.h"
#include <thread>
#include <chrono>
#include <cstring>
#include <sstream>
#include <iomanip>

/**
 * @brief Decodifica una coppia SW1/SW2 in testo leggibile.
 *
 * @param sw1 Primo byte di stato (SW1).
 * @param sw2 Secondo byte di stato (SW2).
 * @return Stringa descrittiva dello stato.
 */
std::string PCSCReader::decodeSW(uint8_t sw1, uint8_t sw2)
{
    if (sw1 == 0x90 && sw2 == 0x00) return "Success";
    if (sw1 == 0x61)                return "More bytes available (SW2 = count)";

    // --- MIFARE / ACR122U ---
    if (sw1 == 0x63 && sw2 == 0x00) return "Authentication failed (wrong key)";
    if (sw1 == 0x65 && sw2 == 0x81) return "Memory failure (write error)";
    if (sw1 == 0x69 && sw2 == 0x82) return "Security status not satisfied (sector not authenticated)";
    if (sw1 == 0x69 && sw2 == 0x86) return "Command not allowed";
    if (sw1 == 0x6F && sw2 == 0x01) return "Card removed / communication error";
    if (sw1 == 0x6F && sw2 == 0x04) return "Authentication failed / no suitable key found";
    if (sw1 == 0x6F && sw2 == 0x12) return "Auth OK but block not readable (access conditions)";

    // --- Standard ISO 7816 ---
    if (sw1 == 0x67 && sw2 == 0x00) return "Wrong length (Lc/Le incorrect)";
    if (sw1 == 0x6A && sw2 == 0x81) return "Function not supported";
    if (sw1 == 0x6A && sw2 == 0x82) return "File/block not found";
    if (sw1 == 0x6A && sw2 == 0x86) return "Incorrect P1/P2";
    if (sw1 == 0x6D && sw2 == 0x00) return "INS not supported";
    if (sw1 == 0x6E && sw2 == 0x00) return "CLA not supported";
    if (sw1 == 0x6F && sw2 == 0x00) return "Unknown error";

    std::ostringstream ss;
    ss << "SW " << std::uppercase << std::hex
       << std::setw(2) << std::setfill('0') << static_cast<int>(sw1)
       << std::setw(2) << std::setfill('0') << static_cast<int>(sw2);
    return ss.str();
}

PCSCReader::PCSCReader() : m_context(0), m_cardHandle(0), m_activeProtocol(0) {}

PCSCReader::~PCSCReader() {
    disconnect();
    releaseContext();
}

void PCSCReader::establishContext()
{
    LONG status = SCardEstablishContext(SCARD_SCOPE_SYSTEM, nullptr, nullptr, &m_context);
    if (status != SCARD_S_SUCCESS)
    {
        Logger::error("Failed to establish context: " + stringifyError(status));
        exit(1);
    }
    Logger::info("Context established");
}

void PCSCReader::releaseContext()
{
    if (m_context != 0)
    {
        SCardReleaseContext(m_context);
        m_context = 0;
    }
}

std::vector<std::string> PCSCReader::listReaders()
{
    LPSTR reader = nullptr;
    DWORD count = SCARD_AUTOALLOCATE;
    LONG status = SCardListReadersA(m_context, nullptr, (LPSTR)&reader, &count);

    if (status != SCARD_S_SUCCESS)
    {
        Logger::error("Failed to list readers: " + stringifyError(status));
        exit(1);
    }

    std::vector<std::string> found_readers;
    found_readers.reserve(4); // Pre-allocazione tipica (1-4 lettori)
    
    LPSTR p = reader;
    while (*p)
    {
        found_readers.emplace_back(p);
        p += strlen(p) + 1;
    }

    if (reader != nullptr)
    {
        SCardFreeMemory(m_context, reader);
    }

    return found_readers;
}

bool PCSCReader::connect(const std::string& readerName)
{
    const LONG status = SCardConnectA(
        m_context,
        readerName.c_str(),
        cShareMode,
        cPreferredProtocols,
        &m_cardHandle,
        &m_activeProtocol
    );

    if (status != SCARD_S_SUCCESS)
    {
        Logger::error("Failed to connect to card: " + stringifyError(status));
        return false;
    }
    
    Logger::info("Connected to card");
    return true;
}

void PCSCReader::disconnect()
{
    if (m_cardHandle != 0)
    {
        SCardDisconnect(m_cardHandle, cDispositionAction);
        m_cardHandle = 0;
    }
}

bool PCSCReader::waitAndConnect(const std::string& readerName, int timeoutSeconds)
{
    const auto start_time = std::chrono::high_resolution_clock::now();
    LONG last_status = SCARD_S_SUCCESS;

    while (true)
    {
        LONG status = SCardConnectA(
            m_context,
            readerName.c_str(),
            cShareMode,
            cPreferredProtocols,
            &m_cardHandle,
            &m_activeProtocol
        );

        if (status == SCARD_S_SUCCESS)
        {
            Logger::info("Tag detected!");
            return true;
        }

        // Carta presente ma non risponde al reset: connessione DIRECT + power-cycle
        if (status == SCARD_W_UNRESPONSIVE_CARD || status == SCARD_W_UNPOWERED_CARD)
        {
            Logger::debug("Card unresponsive, attempting power-cycle reset...");

            LONG direct_status = SCardConnectA(
                m_context,
                readerName.c_str(),
                SCARD_SHARE_DIRECT,
                0,
                &m_cardHandle,
                &m_activeProtocol
            );

            if (direct_status == SCARD_S_SUCCESS)
            {
                LONG reconnect_status = SCardReconnect(
                    m_cardHandle,
                    cShareMode,
                    cPreferredProtocols,
                    SCARD_RESET_CARD,
                    &m_activeProtocol
                );

                if (reconnect_status == SCARD_S_SUCCESS)
                {
                    Logger::info("Tag detected (after reset)!");
                    return true;
                }

                Logger::debug("Reconnect failed: " + stringifyError(reconnect_status));
                SCardDisconnect(m_cardHandle, SCARD_LEAVE_CARD);
                m_cardHandle = 0;
            }
            else
            {
                Logger::debug("Direct connect failed: " + stringifyError(direct_status));
            }
        }

        if (last_status != status)
        {
            Logger::debug("SCardConnect: " + stringifyError(status));
            last_status = status;
        }

        // Verifica timeout
        if (timeoutSeconds > 0)
        {
            auto elapsed = std::chrono::high_resolution_clock::now() - start_time;
            if (std::chrono::duration_cast<std::chrono::seconds>(elapsed).count() >= timeoutSeconds)
            {
                Logger::debug("Timeout waiting for card (last error: " + stringifyError(status) + ")");
                return false;
            }
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
}

CardInfo PCSCReader::getCardInfo()
{
    CardInfo info;

    constexpr DWORD max_atr_size = 33;
    constexpr DWORD max_reader_name_size = 256;
    
    BYTE atr[max_atr_size] = {};
    DWORD atr_length = sizeof(atr);
    char reader_name[max_reader_name_size] = {};
    DWORD reader_length = sizeof(reader_name);
    DWORD state = 0;
    DWORD protocol = 0;

    const LONG status = SCardStatusA(
        m_cardHandle,
        reader_name,
        &reader_length,
        &state,
        &protocol,
        atr,
        &atr_length
    );

    if (status == SCARD_S_SUCCESS)
    {
        info.readerName = std::string(reader_name);
        info.atr.assign(atr, atr + atr_length);

        // Decodifica stato carta
        if (state & SCARD_PRESENT)         info.cardState = "Present";
        else if (state & SCARD_ABSENT)     info.cardState = "Absent";
        else if (state & SCARD_POWERED)    info.cardState = "Powered";
        else if (state & SCARD_NEGOTIABLE) info.cardState = "Negotiable";
        else if (state & SCARD_SPECIFIC)   info.cardState = "Specific";
    }

    return info;
}

APDUResponse PCSCReader::transmit(const std::vector<uint8_t>& command)
{
    APDUResponse response;
    
    Logger::debug("Transmit APDU: " + Hex::bytesToString(command, true));
    
    std::vector<uint8_t> recv_buffer(300);
    DWORD recv_length = static_cast<DWORD>(recv_buffer.size());

    // Seleziona struttura I/O in base al protocollo attivo
    const SCARD_IO_REQUEST* pio_send_pci;
    switch (m_activeProtocol)
    {
        case SCARD_PROTOCOL_T0:
            pio_send_pci = SCARD_PCI_T0;
            break;
        case SCARD_PROTOCOL_T1:
            pio_send_pci = SCARD_PCI_T1;
            break;
        default:
            response.errorMessage = "Unknown protocol";
            Logger::error(response.errorMessage);
            return response;
    }

    LONG status = SCardTransmit(
        m_cardHandle,
        pio_send_pci,
        command.data(),
        static_cast<DWORD>(command.size()),
        nullptr,
        recv_buffer.data(),
        &recv_length
    );

    if (status != SCARD_S_SUCCESS)
    {
        response.errorMessage = "Transmit failed - " + stringifyError(status);
        Logger::error(response.errorMessage);
        return response;
    }

    recv_buffer.resize(recv_length);

    // Parsing SW1 SW2 (ultimi 2 byte)
    if (recv_length >= 2)
    {
        response.sw1 = recv_buffer[recv_length - 2];
        response.sw2 = recv_buffer[recv_length - 1];
        response.success = (response.sw1 == 0x90 && response.sw2 == 0x00);
        
        if (recv_length > 2)
        {
            response.data.assign(recv_buffer.begin(), recv_buffer.end() - 2);
        }
    }
    else
    {
        Logger::error("Invalid response length: " + std::to_string(recv_length));
    }

    return response;
}
