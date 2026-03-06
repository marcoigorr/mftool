#include "command_parser.h"
#include "../core/pcsc_reader.h"
#include "../utils/logger.h"
#include "../utils/atr_parser.h"
#include "../utils/hex.h"
#include "../mifare/key_loader.h"
#include <iostream>
#include <algorithm>
#include <sstream>
#include <chrono>
#include <iomanip>  

CommandParser::CommandParser() = default;
CommandParser::~CommandParser() = default;

void CommandParser::showHelp() const {
    std::cout << "\n========== MFTOOL COMMANDS ==========\n";
    std::cout << "  auth                Pre-authenticate all sectors\n";
    std::cout << "  read <block>        Read single block data\n";
    std::cout << "  write <block> <hex> Write 16 bytes to block\n";
    std::cout << "  dump <sector>       Dump all blocks in sector\n";
    std::cout << "  dumpall             Dump all accessible sectors\n";
    std::cout << "  info                Show card information\n";
    std::cout << "  status              Show authentication status\n";
    std::cout << "  help                Show this help\n";
    std::cout << "  exit                Exit the shell\n";
    std::cout << "=====================================\n\n";
}

void CommandParser::printBlockData(uint8_t blockNumber, const std::vector<uint8_t>& data) {
    std::cout << "  Block " << std::setw(2) << std::setfill('0') << static_cast<int>(blockNumber) << ": ";
    std::cout << Hex::bytesToString(data);
    std::cout << "  |";
    for (uint8_t byte : data) {
        if (byte >= 32 && byte <= 126) {
            std::cout << static_cast<char>(byte);
        } else {
            std::cout << ".";
        }
    }
    std::cout << "|";
    
    if (blockNumber % 4 == 3) {
        std::cout << "  [Sector Trailer]";
    }
    
    std::cout << "\n";
}

bool CommandParser::initializeReader() {
    try {
        reader = std::make_unique<PCSCReader>();
        reader->establishContext();

        auto readers = reader->listReaders();
        if (readers.empty()) {
            Logger::error("No readers found");
            return false;
        }

        Logger::info("Found " + std::to_string(readers.size()) + " reader(s)");
        Logger::info("Using reader: " + readers[0]);

        return true;
    } catch (const std::exception& e) {
        Logger::error(std::string("Initialization failed: ") + e.what());
        return false;
    }
}

void CommandParser::handleAuth() {
    auto start = std::chrono::high_resolution_clock::now();
    
    int authenticated = reader->authenticateAllSectors(keys);
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    std::cout << "\n========== SCAN RESULTS ==========\n";
    std::cout << "Sectors authenticated: " << authenticated << "/16\n";
    std::cout << "Time elapsed: " << duration.count() << " ms\n";
    std::cout << "\n==================================\n";
}

void CommandParser::handleStatus() {
    std::cout << "\n========== AUTH STATUS ==========\n";
    for (uint8_t s = 0; s < 16; s++) {
        std::cout << "Sector " << std::setw(2) << std::setfill('0') << static_cast<int>(s) << ": ";
        if (reader->isSectorAuthenticated(s)) {
            SectorAuth auth = reader->getSectorAuth(s);
            std::cout << "[OK] " << (auth.keyType == 0x60 ? "Key A" : "Key B");
            std::cout << " #" << (auth.keyIndex + 1);
            std::cout << " (" << Hex::bytesToString(auth.key) << ")";
        } else {
            std::cout << "[NOT AUTH]";
        }
        std::cout << "\n";
    }
    std::cout << "=================================\n";
}

void CommandParser::handleInfo() {
    CardInfo currentInfo = reader->getCardInfo();
    std::cout << "Reader: " << currentInfo.readerName << "\n";
    std::cout << "ATR:    " << Hex::bytesToString(currentInfo.atr) << "\n";
    std::cout << "Type:   " << ATRParser::getCardType(currentInfo.atr) << "\n";
    std::cout << "State:  " << currentInfo.cardState << "\n";
}

void CommandParser::handleRead(const std::string& line) {
    std::istringstream iss(line);
    std::string cmd;
    int block;
    
    if (!(iss >> cmd >> block) || block < 0 || block > 63) {
        std::cout << "Usage: read <block>  (0-63)\n";
        return;
    }
    
    uint8_t sector = block / 4;
    
    if (!reader->authenticateSector(sector, keys)) {
        return;
    }
    
    auto data = reader->readBlock(block);
    if (!data.empty()) {
        printBlockData(block, data);
    } else {
        std::cout << "Failed to read block " << block << "\n";
    }
}

void CommandParser::handleWrite(const std::string& line) {
    std::istringstream iss(line);
    std::string cmd;
    int block;
    std::string hexData;
    
    if (!(iss >> cmd >> block >> hexData) || block < 0 || block > 63) {
        std::cout << "Usage: write <block> <32_hex_chars>\n";
        std::cout << "Example: write 4 000102030405060708090A0B0C0D0E0F\n";
        return;
    }

    hexData.erase(std::remove_if(hexData.begin(), hexData.end(), ::isspace), hexData.end());
    std::string extra;
    while (iss >> extra) {
        extra.erase(std::remove_if(extra.begin(), extra.end(), ::isspace), extra.end());
        hexData += extra;
    }

    if (hexData.length() != 32) {
        std::cout << "Error: Expected 32 hex characters (16 bytes), got " << hexData.length() << "\n";
        return;
    }

    auto data = Hex::stringToBytes(hexData);
    if (data.size() != 16) {
        std::cout << "Error: Invalid hex string\n";
        return;
    }

    // Warnings per blocchi critici
    if (block == 0) {
        std::cout << "WARNING: Block 0 contains manufacturer data! Continue? (y/n): ";
        std::string confirm;
        std::getline(std::cin, confirm);
        if (confirm != "y" && confirm != "Y") {
            std::cout << "Write cancelled.\n";
            return;
        }
    }
    if (block % 4 == 3) {
        std::cout << "WARNING: Block " << block << " is a sector trailer (contains keys)! Continue? (y/n): ";
        std::string confirm;
        std::getline(std::cin, confirm);
        if (confirm != "y" && confirm != "Y") {
            std::cout << "Write cancelled.\n";
            return;
        }
    }

    uint8_t sector = block / 4;
    
    if (!reader->isSectorAuthenticated(sector)) {
        std::cout << "Sector " << static_cast<int>(sector) << " not authenticated. Authenticating...\n";
        if (!reader->authenticateSector(sector, keys)) {
            std::cout << "Failed to authenticate sector " << static_cast<int>(sector) << "\n";
            return;
        }
    }

    if (reader->writeBlock(block, data)) {
        std::cout << "Block " << block << " written successfully\n";
    } else {
        std::cout << "Failed to write block " << block << "\n";
    }
}

void CommandParser::handleDump(const std::string& line) {
    std::istringstream iss(line);
    std::string cmd;
    int sector;
    
    if (!(iss >> cmd >> sector) || sector < 0 || sector > 15) {
        std::cout << "Usage: dump <sector>  (0-15)\n";
        return;
    }
    
    if (!reader->isSectorAuthenticated(sector)) {
        if (!reader->authenticateSector(sector, keys)) {
            return;
        }
    }
    
    auto sectorData = reader->readSector(sector);
    
    if (!sectorData.empty()) {
        std::cout << "\n========== Sector " << sector << " ==========\n";
        for (size_t i = 0; i < sectorData.size(); i += 16) {
            uint8_t blockNum = sector * 4 + (i / 16);
            std::vector<uint8_t> blockData(sectorData.begin() + i, sectorData.begin() + i + 16);
            printBlockData(blockNum, blockData);
        }
        std::cout << "===============================\n";
    }
}

void CommandParser::handleDumpAll() {
    std::cout << "\n========== FULL CARD DUMP ==========\n";
    
    int authCount = 0;
    for (uint8_t s = 0; s < 16; s++) {
        if (reader->isSectorAuthenticated(s)) {
            authCount++;
        }
    }
    
    if (authCount == 0) {
        std::cout << "No sectors authenticated. Running scan first...\n";
        reader->authenticateAllSectors(keys);
    }
    
    bool anySuccess = false;
    
    for (uint8_t sector = 0; sector < 16; sector++) {
        if (!reader->isSectorAuthenticated(sector)) {
            std::cout << "\nSector " << static_cast<int>(sector) << ": [NOT ACCESSIBLE]\n";
            continue;
        }
        
        auto sectorData = reader->readSector(sector);
        
        if (!sectorData.empty()) {
            std::cout << "\nSector " << static_cast<int>(sector) << ":\n";
            for (size_t i = 0; i < sectorData.size(); i += 16) {
                uint8_t blockNum = sector * 4 + (i / 16);
                std::vector<uint8_t> blockData(sectorData.begin() + i, sectorData.begin() + i + 16);
                printBlockData(blockNum, blockData);
            }
            anySuccess = true;
        } else {
            std::cout << "\nSector " << static_cast<int>(sector) << ": [READ FAILED]\n";
        }
    }
    
    std::cout << "\n====================================\n";
    if (!anySuccess) {
        std::cout << "Failed to read any sectors\n";
    }
}

void CommandParser::run() {
    if (!initializeReader()) {
        return;
    }

    std::string selectedReader = reader->listReaders()[0];
    bool shouldExit = false;

    // Carica le chiavi all'avvio
    Logger::info("Loading keys from keys/Dump_3A165647.keys...");
    keys = MifareKeyLoader::loadFromFile("keys/Dump_3A165647.keys");
    if (keys.empty()) {
        Logger::warning("No keys loaded, some operations may fail");
    }

    while (!shouldExit) {
        Logger::info("Waiting for a tag... (press Ctrl+C to exit)");

        if (!reader->waitAndConnect(selectedReader)) continue;
         
        CardInfo info = reader->getCardInfo();
        
        std::cout << "\n========== TAG DETECTED ==========\n";
        std::cout << "ATR:  " << Hex::bytesToString(info.atr) << "\n";
        std::cout << "Type: " << ATRParser::getCardType(info.atr) << "\n";
        std::cout << "==================================\n\n";
        std::cout << "Tip: Use 'auth' to pre-authenticate all sectors for faster access.\n";
        std::cout << "Type 'help' for commands, 'exit' to disconnect.\n\n";

        reader->clearAuthCache();

        while (!shouldExit && reader->getCardInfo().cardState == "Present") {
            std::cout << "> ";
            std::string line;
            std::getline(std::cin, line);

            if (reader->getCardInfo().cardState != "Present") {
                break;
            }

            std::istringstream iss(line);
            std::string cmd;
            iss >> cmd;

            if (cmd == "exit") {
                shouldExit = true;
            }
            else if (cmd == "help") {
                showHelp();
            }
            else if (cmd == "auth") {
                handleAuth();
            }
            else if (cmd == "status") {
                handleStatus();
            }
            else if (cmd == "info") {
                handleInfo();
            }
            else if (cmd == "read") {
                handleRead(line);
            }
            else if (cmd == "write") {
                handleWrite(line);
            }
            else if (cmd == "dump") {
                handleDump(line);
            }
            else if (cmd == "dumpall") {
                handleDumpAll();
            }
            else if (!cmd.empty()) {
                std::cout << "Unknown command. Type 'help' for a list of commands.\n";
            }
        }

        if (!shouldExit) {
            Logger::error("Tag removed");
            reader->clearAuthCache();
        }
    }

    reader->disconnect();
    reader->releaseContext();
    Logger::info("Goodbye!");
}