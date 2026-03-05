#include "pcsc_reader.h"
#include "../utils/logger.h"
#include "../utils/pcsc_utils.h"
#include <iostream>
#include <thread>
#include <chrono>
#include <cstring>

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

bool PCSCReader::connect(const std::string& readerName) {
    LONG status = SCardConnectA(
        context,
        readerName.c_str(),
        SCARD_SHARE_SHARED,
        SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
        &cardHandle,
        &activeProtocol
    );

    if (status != SCARD_S_SUCCESS) {
		Logger::error("Failed to connect to card: " + stringifyError(status));
        return false;
    }
    Logger::info("Connected to card");
    return true;
}

void PCSCReader::disconnect() {
    if (cardHandle != 0) {
        SCardDisconnect(cardHandle, SCARD_LEAVE_CARD);
        cardHandle = 0;
    }
}

bool PCSCReader::waitAndConnect(const std::string& readerName, int timeoutSeconds) {
    auto startTime = std::chrono::high_resolution_clock::now();

    while (true) {
        // Tenta di connettersi al tag
        LONG status = SCardConnectA(
            context,
            readerName.c_str(),
            SCARD_SHARE_SHARED,
            SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
            &cardHandle,
            &activeProtocol
        );

        if (status == SCARD_S_SUCCESS) {            
            Logger::info("Tag detected!");
            return true;
        }

        // Controlla timeout
        if (timeoutSeconds > 0) {
            auto elapsed = std::chrono::high_resolution_clock::now() - startTime;
            if (std::chrono::duration_cast<std::chrono::seconds>(elapsed).count() >= timeoutSeconds) {
                Logger::error("Timeout waiting for card");
                return false;
            }
        }

        // Aspetta un po' prima di riprovare
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
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
    std::vector<uint8_t> response(300);
    unsigned long responseLength = response.size();

    const SCARD_IO_REQUEST* pioSendPci = nullptr;
    switch (activeProtocol) {
        case SCARD_PROTOCOL_T0:
            pioSendPci = SCARD_PCI_T0;
            break;
        case SCARD_PROTOCOL_T1:
            pioSendPci = SCARD_PCI_T1;
            break;
        default:
            Logger::error("Unknown protocol");
            return std::vector<uint8_t>();
    }

    SCARD_IO_REQUEST pioRecvPci;
    LONG status = SCardTransmit(
        cardHandle,
        pioSendPci,
        command.data(),
        command.size(),
        &pioRecvPci,
        response.data(),
        &responseLength
    );

    if (status != SCARD_S_SUCCESS) {
        Logger::error("Transmit failed: " + stringifyError(status));
        return std::vector<uint8_t>();
    }

    response.resize(responseLength);
    return response;
}