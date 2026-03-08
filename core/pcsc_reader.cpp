#include "pcsc_reader.h"
#include "../utils/logger.h"
#include "../utils/pcsc_utils.h"
#include <iostream>
#include <thread>
#include <chrono>
#include <cstring>
#include <sstream>
#include <iomanip>

PCSCReader::PCSCReader() : context(0), cardHandle(0), activeProtocol(0) {}

PCSCReader::~PCSCReader() {
    disconnect();
    releaseContext();
}

void PCSCReader::establishContext() {
    LONG status = SCardEstablishContext(SCARD_SCOPE_SYSTEM, nullptr, nullptr, &context);
    if (status != SCARD_S_SUCCESS) {
        Logger::error("Failed to establish context: " + stringifyError(status));
        exit(1);
    }
    Logger::info("Context established");
}

void PCSCReader::releaseContext() {
    if (context != 0) {
        SCardReleaseContext(context);
        context = 0;
    }
}

std::vector<std::string> PCSCReader::listReaders() {
    LPSTR reader = NULL;
    DWORD count = SCARD_AUTOALLOCATE;
    LONG status = SCardListReadersA(context, NULL, (LPSTR)&reader, &count);

    if (status != SCARD_S_SUCCESS) {
        Logger::error("Failed to list readers: " + stringifyError(status));
        exit(1);
    }

    std::vector<std::string> foundReaders;
    LPSTR p = reader;
    while (*p) {
        foundReaders.emplace_back(p);
        p += strlen(p) + 1;
    }

    if (reader != NULL) {
        SCardFreeMemory(context, reader);
        reader = NULL;
    }

    return foundReaders;
}

bool PCSCReader::waitAndConnect(const std::string& readerName, int timeoutSeconds) {
    auto startTime = std::chrono::high_resolution_clock::now();

    while (true) {
        // SCARD_SHARE_EXCLUSIVE garantisce accesso atomico alla sequenza MIFARE
        // (LOAD KEY + GENERAL AUTH sono due APDU distinte che devono essere
        //  consecutive senza interleaving da altri processi).
        LONG status = SCardConnectA(
            context,
            readerName.c_str(),
            SCARD_SHARE_EXCLUSIVE,
            SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
            &cardHandle,
            &activeProtocol
        );

        // Fallback SHARED se EXCLUSIVE non e' disponibile
        if (status == SCARD_E_SHARING_VIOLATION)
        {
            Logger::debug("EXCLUSIVE sharing violation, fallback to SHARED");
            status = SCardConnectA(
                context,
                readerName.c_str(),
                SCARD_SHARE_SHARED,
                SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
                &cardHandle,
                &activeProtocol
            );
        }

        if (status == SCARD_S_SUCCESS)
        {
            Logger::info("Connected to card");
            Logger::debug("Active protocol: 0x" + [&]{ std::stringstream s;
                          s << std::hex << activeProtocol; return s.str(); }()
                          + (activeProtocol == SCARD_PROTOCOL_T0 ? " (T0)"
                           : activeProtocol == SCARD_PROTOCOL_T1 ? " (T1)" : " (other)"));
            return true;
        }

        // Card non ancora presente, controlla il timeout prima di riprovare
        if (timeoutSeconds > 0)
        {
            auto elapsed = std::chrono::high_resolution_clock::now() - startTime;
            if (std::chrono::duration_cast<std::chrono::seconds>(elapsed).count() >= timeoutSeconds)
            {
                Logger::error("Timeout waiting for card");
                return false;
            }
        }

        // Aspetta prima di riprovare
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
}


void PCSCReader::disconnect() {
    if (cardHandle != 0) {
        SCardDisconnect(cardHandle, SCARD_LEAVE_CARD);
        cardHandle = 0;
    }
}

CardInfo PCSCReader::getCardInfo() {
    CardInfo info;

    BYTE atr[MAX_ATR_SIZE] = "";
    DWORD atrLength = sizeof(atr);
    char readerName[MAX_READERNAME] = "";
    DWORD readerLength = sizeof(readerName);
    DWORD state = 0;
    DWORD protocol = 0;

    LONG status = SCardStatusA(
        cardHandle,
        readerName,
        &readerLength,
        &state,
        &protocol,
        atr,
        &atrLength
    );

    if (status == SCARD_S_SUCCESS) {
        info.readerName = std::string(readerName);
        info.atr.assign(atr, atr + atrLength);

        // Determina lo stato del tag
        if (state & SCARD_PRESENT) {
            info.cardState = "Present";
        } else if (state & SCARD_ABSENT) {
            info.cardState = "Absent";
        } else if (state & SCARD_POWERED) {
            info.cardState = "Powered";
        } else if (state & SCARD_NEGOTIABLE) {
            info.cardState = "Negotiable";
        } else if (state & SCARD_SPECIFIC) {
            info.cardState = "Specific";
        }
    }

    return info;
}

std::vector<uint8_t> PCSCReader::transmit(const std::vector<uint8_t>& command) {
    const SCARD_IO_REQUEST* pioSendPci;
    switch (activeProtocol)
    {
        case SCARD_PROTOCOL_T0: pioSendPci = SCARD_PCI_T0; break;
        case SCARD_PROTOCOL_T1: pioSendPci = SCARD_PCI_T1; break;
        default:
            Logger::debug("activeProtocol=0x" + [&]{ std::stringstream s;
                          s << std::hex << activeProtocol; return s.str(); }()
                          + " non riconosciuto, uso T1 (ACR122U default)");
            pioSendPci = SCARD_PCI_T1;
            break;
    }

    std::vector<uint8_t> response(258);
    DWORD responseLength = static_cast<DWORD>(response.size());

    LONG status = SCardTransmit(
        cardHandle,
        pioSendPci,
        command.data(),
        static_cast<DWORD>(command.size()),
        nullptr,
        response.data(),
        &responseLength
    );

    // La carta contactless può uscire dal campo RF durante una scansione lunga.
    // SCardReconnect ripristina il handle senza dover rifare SCardConnect.
    if (status == SCARD_W_RESET_CARD)
    {
        Logger::debug("Card reset detected, reconnecting...");
        LONG reconnStatus = SCardReconnect(
            cardHandle,
            SCARD_SHARE_EXCLUSIVE,
            SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
            SCARD_RESET_CARD,
            &activeProtocol
        );

        if (reconnStatus == SCARD_E_SHARING_VIOLATION)
        {
            Logger::debug("EXCLUSIVE reconnect failed, fallback to SHARED");
            reconnStatus = SCardReconnect(
                cardHandle,
                SCARD_SHARE_SHARED,
                SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
                SCARD_RESET_CARD,
                &activeProtocol
            );
        }

        if (reconnStatus != SCARD_S_SUCCESS)
        {
            Logger::error("Reconnect failed: " + stringifyError(reconnStatus));
            return {};
        }

        Logger::debug("Reconnected, retrying transmit...");
        responseLength = static_cast<DWORD>(response.size());
        status = SCardTransmit(
            cardHandle,
            pioSendPci,
            command.data(),
            static_cast<DWORD>(command.size()),
            nullptr,
            response.data(),
            &responseLength
        );
    }

    if (status != SCARD_S_SUCCESS) {
        std::stringstream hexCode;
        hexCode << "0x" << std::hex << std::uppercase
                << std::setw(8) << std::setfill('0') << (unsigned long)status;
        Logger::error("SCardTransmit failed: " + stringifyError(status)
                      + " (" + hexCode.str() + ")");
        return {};
    }

    response.resize(responseLength);
    return response;
}

std::vector<uint8_t> PCSCReader::buildAPDU(uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2,
                                             const std::vector<uint8_t>& data, uint8_t le) {
    std::vector<uint8_t> apdu;

    // Header (CLA, INS, P1, P2)
    apdu.push_back(cla);
    apdu.push_back(ins);
    apdu.push_back(p1);
    apdu.push_back(p2);

    // Se ci sono dati, aggiungi Lc e i dati
    if (!data.empty()) {
        if (data.size() > 255) {
            Logger::error("APDU data too long (max 255 bytes)");
            return apdu;
        }
        apdu.push_back(static_cast<uint8_t>(data.size())); // Lc
        apdu.insert(apdu.end(), data.begin(), data.end());
    }

    // Se Le è specificato, aggiungilo
    if (le > 0 || (data.empty() && le == 0)) {
        apdu.push_back(le);
    }

    // Log del comando costruito
    std::stringstream ss;
    ss << "Built APDU: ";
    for (auto byte : apdu) {
        ss << std::hex << std::uppercase << std::setw(2) << std::setfill('0') 
           << static_cast<int>(byte) << " ";
    }
    Logger::debug(ss.str());

    return apdu;
}

// ---------------------------------------------------------------------------
// transmitAPDU
//
// Wrapper su transmit() che separa i dati di risposta dallo Status Word
// (SW1 SW2 = ultimi 2 byte). success = true solo se SW == 90 00.
// ---------------------------------------------------------------------------
APDUResponse PCSCReader::transmitAPDU(const std::vector<uint8_t>& command)
{
    APDUResponse result;

    auto raw = transmit(command);

    // Risposta minima attesa: almeno SW1 + SW2 (2 byte)
    if (raw.size() < 2)
    {
        result.errorMessage = "Response too short (no SW)";
        return result;
    }

    uint8_t sw1 = raw[raw.size() - 2];
    uint8_t sw2 = raw[raw.size() - 1];

    // Estrai i dati (tutto tranne gli ultimi 2 byte)
    result.data.assign(raw.begin(), raw.end() - 2);
    result.sw1     = sw1;
    result.sw2     = sw2;
    result.success = (sw1 == 0x90 && sw2 == 0x00);

    if (!result.success)
    {
        std::stringstream swStr;
        swStr << "SW: " << std::uppercase << std::hex
              << std::setw(2) << std::setfill('0') << (int)sw1
              << std::setw(2) << std::setfill('0') << (int)sw2;
        result.errorMessage = swStr.str();
    }

    return result;
}