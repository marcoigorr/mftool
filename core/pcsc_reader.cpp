#include "pcsc_reader.h"
#include "../utils/logger.h"
#include "../utils/hex.h"
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

// ========== MIFARE Classic Operations ==========

bool PCSCReader::loadAuthenticationKey(uint8_t keyNumber, const std::vector<uint8_t>& key) {
    if (key.size() != 6) {
        Logger::error("Invalid key size (must be 6 bytes)");
        return false;
    }

    std::vector<uint8_t> command = { 0xFF, 0x82, 0x00, 0x00, 0x06 };
	for (int i = 0; i < 6; i++) {
        command.push_back(key[i]);
    }

    auto response = transmit(command);
    
    if (response.size() >= 2 && response[response.size() - 2] == 0x90 && response[response.size() - 1] == 0x00) {
        return true;
    }

    Logger::error("Failed to load authentication key");
    return false;
}

bool PCSCReader::authenticate(uint8_t blockNumber, uint8_t keyType, uint8_t keyNumber) {
    std::vector<uint8_t> command = { 
        0xFF, 0x86, 0x00, 0x00, 0x05, 0x01, 0x00, blockNumber, keyType, keyNumber
    };

    auto response = transmit(command);

    if (response.size() >= 2 && response[response.size() - 2] == 0x90 && response[response.size() - 1] == 0x00) {
        Logger::debug("Authentication successful for block " + std::to_string(blockNumber) + 
                     " using " + (keyType == 0x60 ? "Key A" : "Key B"));
        return true;
    }

    return false;
}

bool PCSCReader::tryAuthenticate(uint8_t blockNumber, const std::vector<std::vector<uint8_t>>& keys) {
    const uint8_t keyTypes[] = { 0x60, 0x61 };
    const char* keyTypeNames[] = { "Key A", "Key B" };

    for (int typeIdx = 0; typeIdx < 2; typeIdx++) {
        uint8_t keyType = keyTypes[typeIdx];
        
        for (size_t i = 0; i < keys.size(); i++) {
            if (!loadAuthenticationKey(0x00, keys[i])) {
                continue;
            }

            if (authenticate(blockNumber, keyType, 0x00)) {
                Logger::info("Authentication successful with " + std::string(keyTypeNames[typeIdx]) + 
                           " #" + std::to_string(i + 1) + " of " + std::to_string(keys.size()));
                return true;
            }
        }
    }

    return false;
}

bool PCSCReader::authenticateSector(uint8_t sector, const std::vector<std::vector<uint8_t>>& keys) {
    if (isSectorAuthenticated(sector)) {
        Logger::debug("Sector " + std::to_string(sector) + " already authenticated");
        return true;
    }

    uint8_t firstBlock = sector * 4;
    const uint8_t keyTypes[] = { 0x60, 0x61 };
    const char* keyTypeNames[] = { "Key A", "Key B" };

    Logger::debug("Authenticating sector " + std::to_string(sector) + "...");

    // CARICA OGNI CHIAVE UNA SOLA VOLTA
    for (size_t i = 0; i < keys.size(); i++) {
        std::string keyHex = Hex::bytesToString(keys[i]);
        Logger::debug("Trying key #" + std::to_string(i + 1) + ": " + keyHex);
        
        if (!loadAuthenticationKey(0x00, keys[i])) {
            Logger::warning("Failed to load key #" + std::to_string(i + 1) + ": " + keyHex);
            continue;
        }
        
        // Prova entrambi i tipi di chiave DOPO aver caricato
        for (int typeIdx = 0; typeIdx < 2; typeIdx++) {
            uint8_t keyType = keyTypes[typeIdx];

            if (authenticate(firstBlock, keyType, 0x00)) {
                SectorAuth auth;
                auth.authenticated = true;
                auth.key = keys[i];
                auth.keyType = keyType;
                auth.keyIndex = i;
                
                sectorAuthCache[sector] = auth;
                
                Logger::info("Sector " + std::to_string(sector) + " authenticated with " + 
                           std::string(keyTypeNames[typeIdx]) + " #" + std::to_string(i + 1) + 
                           " (" + keyHex + ")");
                return true;
            }
        }
    }

    Logger::warning("Failed to authenticate sector " + std::to_string(sector));
    return false;
}

int PCSCReader::authenticateAllSectors(const std::vector<std::vector<uint8_t>>& keys) {
    Logger::info("Pre-authenticating all sectors...");
    clearAuthCache();
    
    int successCount = 0;
    
    // MIFARE Classic 1K ha 16 settori
    for (uint8_t sector = 0; sector < 16; sector++) {
        if (authenticateSector(sector, keys)) {
            successCount++;
        }
    }
    
    Logger::info("Authentication complete: " + std::to_string(successCount) + "/16 sectors accessible");
    return successCount;
}

bool PCSCReader::isSectorAuthenticated(uint8_t sector) const {
    auto it = sectorAuthCache.find(sector);
    return (it != sectorAuthCache.end() && it->second.authenticated);
}

SectorAuth PCSCReader::getSectorAuth(uint8_t sector) const {
    auto it = sectorAuthCache.find(sector);
    if (it != sectorAuthCache.end()) {
        return it->second;
    }
    return SectorAuth();
}

void PCSCReader::clearAuthCache() {
    sectorAuthCache.clear();
    Logger::debug("Authentication cache cleared");
}

std::vector<uint8_t> PCSCReader::readBlock(uint8_t blockNumber) {
    uint8_t sector = blockNumber / 4;
    
    // Se il settore non è autenticato, errore
    if (!isSectorAuthenticated(sector)) {
        Logger::error("Sector " + std::to_string(sector) + " not authenticated. Use authenticateSector() first.");
        return std::vector<uint8_t>();
    }
    
    // Leggi il blocco direttamente (l'autenticazione persiste per tutto il settore)
    std::vector<uint8_t> command = { 0xFF, 0xB0, 0x00, blockNumber, 0x10 };
    auto response = transmit(command);

    // Gestisce errore di autenticazione scaduta (63 00)
    if (response.size() >= 2 && response[response.size() - 2] == 0x63 && response[response.size() - 1] == 0x00) {
        Logger::warning("Authentication expired for sector " + std::to_string(sector) + ". Re-authenticating...");
        
        // Recupera le credenziali dalla cache
        SectorAuth auth = getSectorAuth(sector);
        if (auth.authenticated) {
            // Ri-autentica con la stessa chiave
            if (loadAuthenticationKey(0x00, auth.key) && authenticate(blockNumber, auth.keyType, 0x00)) {
                Logger::debug("Re-authentication successful");
                
                // Riprova la lettura
                response = transmit(command);
            } else {
                Logger::error("Failed to re-authenticate sector " + std::to_string(sector));
                sectorAuthCache.erase(sector);
                return std::vector<uint8_t>();
            }
        }
    }

    if (response.size() >= 2 && response[response.size() - 2] == 0x90 && response[response.size() - 1] == 0x00) {
        response.resize(response.size() - 2);
        Logger::debug("Block " + std::to_string(blockNumber) + " read successfully");
        return response;
    }

    Logger::error("Failed to read block " + std::to_string(blockNumber) + 
                 " (Status: " + Hex::bytesToString(response) + ")");
    return std::vector<uint8_t>();
}

bool PCSCReader::writeBlock(uint8_t blockNumber, const std::vector<uint8_t>& data) {
    if (data.size() != 16) {
        Logger::error("Invalid data size (must be 16 bytes)");
        return false;
    }

    uint8_t sector = blockNumber / 4;
    
    // Se il settore non è autenticato, errore
    if (!isSectorAuthenticated(sector)) {
        Logger::error("Sector " + std::to_string(sector) + " not authenticated. Use authenticateSector() first.");
        return false;
    }

    // Scrivi il blocco direttamente (l'autenticazione persiste per tutto il settore)
    std::vector<uint8_t> command = { 0xFF, 0xD6, 0x00, blockNumber, 0x10 };
    command.insert(command.end(), data.begin(), data.end());

    auto response = transmit(command);

    if (response.size() >= 2 && response[response.size() - 2] == 0x90 && response[response.size() - 1] == 0x00) {
        Logger::debug("Block " + std::to_string(blockNumber) + " written successfully");
        return true;
    }

    Logger::error("Failed to write block " + std::to_string(blockNumber));
    return false;
}

std::vector<uint8_t> PCSCReader::readSector(uint8_t sector) {
    std::vector<uint8_t> sectorData;

    if (!isSectorAuthenticated(sector)) {
        Logger::error("Sector " + std::to_string(sector) + " not authenticated");
        return std::vector<uint8_t>();
    }

    uint8_t firstBlock = sector * 4;
    uint8_t lastBlock = firstBlock + 3;

    Logger::debug("Reading sector " + std::to_string(sector) + " (blocks " + 
                 std::to_string(firstBlock) + "-" + std::to_string(lastBlock) + ")");

    // Legge tutti i blocchi del settore
    for (uint8_t block = firstBlock; block <= lastBlock; block++) {
        auto blockData = readBlock(block);
        if (blockData.empty()) {
            Logger::error("Failed to read block " + std::to_string(block));
            return std::vector<uint8_t>();
        }
        sectorData.insert(sectorData.end(), blockData.begin(), blockData.end());
    }

    Logger::debug("Sector " + std::to_string(sector) + " read successfully (" + 
                 std::to_string(sectorData.size()) + " bytes)");
    return sectorData;
}

std::vector<uint8_t> PCSCReader::readSectorWithAuth(uint8_t sector, const std::vector<std::vector<uint8_t>>& keys) {
    // Se non è autenticato, prova ad autenticare
    if (!isSectorAuthenticated(sector)) {
        if (!authenticateSector(sector, keys)) {
            return std::vector<uint8_t>();
        }
    }
    
    return readSector(sector);
}