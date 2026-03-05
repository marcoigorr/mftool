#include "command_parser.h"
#include "../core/pcsc_reader.h"
#include "../utils/logger.h"
#include "../utils/atr_parser.h"
#include "../utils/hex.h"
#include <iostream>
#include <algorithm>
#include <sstream>

CommandParser::CommandParser() = default;
CommandParser::~CommandParser() = default;

void CommandParser::showHelp() const {
    std::cout << "\n========== MFTOOL COMMANDS ==========\n";
    std::cout << "  read <block>        Read block data\n";
    std::cout << "  write <block>       Write block data\n";
    std::cout << "  dump <sector>       Dump sector data\n";
    std::cout << "  help                Show this help\n";
    std::cout << "  exit                Exit the shell\n";
    std::cout << "=====================================\n\n";
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

    while (!shouldExit) {
        // Aspetta il tag
		Logger::info("Waiting for a tag... (press Ctrl+C to exit)");
        if (!reader->waitAndConnect(selectedReader)) {
            continue;
        }

        // Tag rilevato, mostra info

        CardInfo info = reader->getCardInfo();
        
        Logger::info("ATR: " + Hex::bytesToString(info.atr));
		Logger::info("TYPE: " + ATRParser::getCardType(info.atr) + "\n");
        std::cout << "Type 'help' for commands, 'exit' to disconnect.\n\n";

        // Shell interattiva mentre il tag è presente
        while (!shouldExit && reader->getCardInfo().cardState == "Present") {
            std::cout << "> ";
            std::string line;
            std::getline(std::cin, line);

            // Controlla nuovamente dopo aver ricevuto input
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
            else if (cmd == "read") {
                int block;
                iss >> block;
                std::cout << "Reading block " << block << "...\n";
            }
            else if (cmd == "write") {
                int block;
                std::string data;
                iss >> block >> data;
                std::cout << "Writing to block " << block << "...\n";
            }
            else if (cmd == "dump") {
                int sector;
                iss >> sector;
                std::cout << "Dumping sector " << sector << "...\n";
            }
            else if (!cmd.empty()) {
                std::cout << "Unknown command. Type 'help' for a list of commands.\n";
            }
        }

        if (!shouldExit) {
            Logger::error("Tag removed");
        }
            
    }

    reader->disconnect();
    reader->releaseContext();
}