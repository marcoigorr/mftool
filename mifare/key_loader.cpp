#include "key_loader.h"
#include "../utils/hex.h"
#include "../utils/logger.h"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cctype>

std::vector<std::vector<uint8_t>> MifareKeyLoader::loadFromFile(const std::string& filename) {
    std::vector<std::vector<uint8_t>> keys;
    std::ifstream file(filename);

    if (!file.is_open()) {
        Logger::error("Failed to open key file: " + filename);
        return keys;
    }

    std::string line;
    int lineNumber = 0;

    while (std::getline(file, line)) {
        lineNumber++;

        // Rimuove spazi bianchi all'inizio e alla fine
        line.erase(0, line.find_first_not_of(" \t\r\n"));
        line.erase(line.find_last_not_of(" \t\r\n") + 1);

        // Salta commenti e righe vuote
        if (line.empty() || line[0] == '#') {
            continue;
        }

        // Rimuove tutti gli spazi interni
        line.erase(std::remove_if(line.begin(), line.end(), ::isspace), line.end());

        // Verifica lunghezza corretta (12 caratteri hex = 6 bytes)
        if (line.length() != 12) {
            Logger::warning("Invalid key at line " + std::to_string(lineNumber) + 
                          " (expected 12 hex chars, got " + std::to_string(line.length()) + ")");
            continue;
        }

        // Converte stringa hex in bytes
        auto key = parseKey(line);
        if (key.size() == 6) {
            keys.push_back(key);
            Logger::debug("Loaded key: " + line);
        } else {
            Logger::warning("Failed to parse key at line " + std::to_string(lineNumber));
        }
    }

    file.close();
    
    if (keys.empty()) {
        Logger::warning("No valid keys found in " + filename);
    } else {
        Logger::info("Loaded " + std::to_string(keys.size()) + " keys from " + filename);
    }

    return keys;
}

std::vector<uint8_t> MifareKeyLoader::parseKey(const std::string& hexString) {
    // Verifica che contenga solo caratteri esadecimali
    for (char c : hexString) {
        if (!std::isxdigit(static_cast<unsigned char>(c))) {
            return std::vector<uint8_t>();
        }
    }

    // Converte usando l'utility Hex esistente
    return Hex::stringToBytes(hexString);
}