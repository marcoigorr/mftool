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
    std::cout << "  scan                Pre-authenticate all sectors\n";
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
    // Numero del blocco con padding
    std::cout << "  Block " << std::setw(2) << std::setfill('0') << static_cast<int>(blockNumber) << ": ";
    
    // Dati in esadecimale
    std::cout << Hex::bytesToString(data);
    
    // Padding per allineare la colonna ASCII (se necessario)
    // Ogni byte in hex sono 2 char + 1 spazio = 3 char per byte
    // 16 bytes = 48 char - 1 spazio finale = 47 char
    
    // Mostra caratteri ASCII stampabili
    std::cout << "  |";
    for (uint8_t byte : data) {
        // Caratteri stampabili ASCII (32-126)
        if (byte >= 32 && byte <= 126) {
            std::cout << static_cast<char>(byte);
        } else {
            std::cout << ".";
        }
    }
    std::cout << "|";
    
    // Se è un blocco trailer (ultimo del settore), aggiungi nota
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

void CommandParser::run() {
    if (!initializeReader()) {
        return;
    }

    std::string selectedReader = reader->listReaders()[0];
    bool shouldExit = false;

    // Carica le chiavi all'avvio
    Logger::info("Loading keys from keys/Dump_3A165647.keys...");
    auto keys = MifareKeyLoader::loadFromFile("keys/Dump_3A165647.keys");
    if (keys.empty()) {
        Logger::warning("No keys loaded, some operations may fail");
    }

    while (!shouldExit) {
        // Aspetta il tag
        Logger::info("Waiting for a tag... (press Ctrl+C to exit)");
        if (!reader->waitAndConnect(selectedReader)) {
            continue;
        }

        // Tag rilevato, mostra info
        CardInfo info = reader->getCardInfo();
        
        std::cout << "\n========== TAG DETECTED ==========\n";
        std::cout << "ATR:  " << Hex::bytesToString(info.atr) << "\n";
        std::cout << "Type: " << ATRParser::getCardType(info.atr) << "\n";
        std::cout << "==================================\n\n";
        std::cout << "Tip: Use 'scan' to pre-authenticate all sectors for faster access.\n";
        std::cout << "Type 'help' for commands, 'exit' to disconnect.\n\n";

        // Pulisce la cache delle autenticazioni per il nuovo tag
        reader->clearAuthCache();

        // Shell interattiva mentre il tag è presente
        while (!shouldExit && reader->getCardInfo().cardState == "Present") {
            std::cout << "> ";
            std::string line;
            std::getline(std::cin, line);

            // Controlla se il tag è ancora presente
            if (reader->getCardInfo().cardState != "Present") {
                break;
            }

            std::istringstream iss(line);
            std::string cmd;
            iss >> cmd;

            if (cmd == "exit") {
                shouldExit = true;
                break;
            }
            else if (cmd == "help") {
                showHelp();
            }
            else if (cmd == "scan") {
                std::cout << "Scanning card and pre-authenticating sectors...\n";
                auto start = std::chrono::high_resolution_clock::now();
                
                int authenticated = reader->authenticateAllSectors(keys);
                
                auto end = std::chrono::high_resolution_clock::now();
                auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
                
                std::cout << "\n========== SCAN RESULTS ==========\n";
                std::cout << "Sectors authenticated: " << authenticated << "/16\n";
                std::cout << "Time elapsed: " << duration.count() << " ms\n";
                
                // Mostra quali settori sono accessibili
                std::cout << "\nAccessible sectors: ";
                for (uint8_t s = 0; s < 16; s++) {
                    if (reader->isSectorAuthenticated(s)) {
                        std::cout << static_cast<int>(s) << " ";
                    }
                }
                std::cout << "\n==================================\n";
            }
            else if (cmd == "status") {
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
            else if (cmd == "info") {
                CardInfo currentInfo = reader->getCardInfo();
                std::cout << "Reader: " << currentInfo.readerName << "\n";
                std::cout << "ATR:    " << Hex::bytesToString(currentInfo.atr) << "\n";
                std::cout << "Type:   " << ATRParser::getCardType(currentInfo.atr) << "\n";
                std::cout << "State:  " << currentInfo.cardState << "\n";
            }
            else if (cmd == "read") {
                int block;
                if (!(iss >> block) || block < 0 || block > 63) {
                    std::cout << "Usage: read <block>  (0-63)\n";
                    continue;
                }
                
                uint8_t sector = block / 4;
                
                // Se non è autenticato, prova ad autenticare
                if (!reader->isSectorAuthenticated(sector)) {
                    std::cout << "Sector " << static_cast<int>(sector) << " not authenticated. Authenticating...\n";
                    if (!reader->authenticateSector(sector, keys)) {
                        std::cout << "Failed to authenticate sector " << static_cast<int>(sector) << "\n";
                        continue;
                    }
                }
                
                auto data = reader->readBlock(block);
                if (!data.empty()) {
                    printBlockData(block, data);
                } else {
                    std::cout << "Failed to read block " << block << "\n";
                }
            }
            else if (cmd == "write") {
                int block;
                std::string hexData;
                if (!(iss >> block >> hexData) || block < 0 || block > 63) {
                    std::cout << "Usage: write <block> <32_hex_chars>\n";
                    std::cout << "Example: write 4 00010203040506070809 0A0B0C0D0E0F\n";
                    continue;
                }

                hexData.erase(std::remove_if(hexData.begin(), hexData.end(), ::isspace), hexData.end());
                std::string extra;
                while (iss >> extra) {
                    extra.erase(std::remove_if(extra.begin(), extra.end(), ::isspace), extra.end());
                    hexData += extra;
                }

                if (hexData.length() != 32) {
                    std::cout << "Error: Expected 32 hex characters (16 bytes), got " << hexData.length() << "\n";
                    continue;
                }

                auto data = Hex::stringToBytes(hexData);
                if (data.size() != 16) {
                    std::cout << "Error: Invalid hex string\n";
                    continue;
                }

                // ATTENZIONE: Blocco 0 e blocchi trailer
                if (block == 0) {
                    std::cout << "WARNING: Block 0 contains manufacturer data! Continue? (y/n): ";
                    std::string confirm;
                    std::getline(std::cin, confirm);
                    if (confirm != "y" && confirm != "Y") {
                        std::cout << "Write cancelled.\n";
                        continue;
                    }
                }
                if (block % 4 == 3) {
                    std::cout << "WARNING: Block " << block << " is a sector trailer (contains keys)! Continue? (y/n): ";
                    std::string confirm;
                    std::getline(std::cin, confirm);
                    if (confirm != "y" && confirm != "Y") {
                        std::cout << "Write cancelled.\n";
                        continue;
                    }
                }

                uint8_t sector = block / 4;
                
                // Se non è autenticato, prova ad autenticare
                if (!reader->isSectorAuthenticated(sector)) {
                    std::cout << "Sector " << static_cast<int>(sector) << " not authenticated. Authenticating...\n";
                    if (!reader->authenticateSector(sector, keys)) {
                        std::cout << "Failed to authenticate sector " << static_cast<int>(sector) << "\n";
                        continue;
                    }
                }

                if (reader->writeBlock(block, data)) {
                    std::cout << "Block " << block << " written successfully\n";
                } else {
                    std::cout << "Failed to write block " << block << "\n";
                }
            }
            else if (cmd == "dump") {
                int sector;
                if (!(iss >> sector) || sector < 0 || sector > 15) {
                    std::cout << "Usage: dump <sector>  (0-15)\n";
                    continue;
                }
                
                // Se non è autenticato, prova ad autenticare
                if (!reader->isSectorAuthenticated(sector)) {
                    std::cout << "Sector " << sector << " not authenticated. Authenticating...\n";
                    if (!reader->authenticateSector(sector, keys)) {
                        std::cout << "Failed to authenticate sector " << sector << "\n";
                        continue;
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
            else if (cmd == "dumpall") {
                std::cout << "\n========== FULL CARD DUMP ==========\n";
                
                // Se non è stato fatto lo scan, fallo ora
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
            else if (!cmd.empty()) {
                std::cout << "Unknown command. Type 'help' for a list of commands.\n";
            }
        }

        if (!shouldExit) {
            Logger::error("Tag removed");
            reader->clearAuthCache();
            std::cout << "\n";
        }
    }

    reader->disconnect();
    reader->releaseContext();
    Logger::info("Goodbye!");
}