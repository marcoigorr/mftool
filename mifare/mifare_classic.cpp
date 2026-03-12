/**
 * @file mifare_classic.cpp
 * @brief Implementazione della classe MifareClassic per la gestione di tag MIFARE Classic 1K.
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
#include "mifare_classic.h"
#include "../utils/logger.h"
#include "../utils/hex.h"
#include <fstream>
#include <algorithm>
#include <cctype>


MifareClassic::MifareClassic(PCSCReader& reader)
    : m_reader(reader)
{
}

int MifareClassic::toAbsBlock(int sector, int relBlock)
{
    return sector * BLOCKS_PER_SECTOR + relBlock;
}

std::vector<MifareKey> MifareClassic::loadKeys(const std::string& path)
{
    std::vector<MifareKey> keys;
    keys.reserve(32);

    std::ifstream file(path);
    if (!file.is_open())
    {
        Logger::error("Cannot open key file: " + path);
        return keys;
    }

    std::string line;
    while (std::getline(file, line))
    {
        // Rimuovi whitespace
        line.erase(std::remove_if(line.begin(), line.end(), ::isspace), line.end());
        if (line.empty() || line[0] == '#') continue;
        if (line.size() != 12) continue;

        MifareKey key{};
        bool valid = true;
        
        for (size_t i = 0; i < 6; ++i)
        {
            try 
            { 
                key[i] = static_cast<uint8_t>(
                    std::stoul(line.substr(i * 2, 2), nullptr, 16)
                );
            }
            catch (...) 
            { 
                valid = false; 
                break; 
            }
        }

        if (valid)
        {
            keys.emplace_back(key);  // emplace_back invece di push_back
            
            Logger::debug("Loaded key from file: " + Hex::bytesToString(key));
        }
    }

    Logger::debug("Loaded " + std::to_string(keys.size()) + " key(s) from " + path);
    return keys;
}

bool MifareClassic::authenticate(int sector, const MifareKey& key, char keyType)
{        
    // Passo 1: carica la chiave nel lettore
    std::vector<uint8_t> apdu = { 0xFF, 0x82, 0x00, 0x00, 0x06, key[0], key[1], key[2], key[3], key[4], key[5] };
    auto response = m_reader.transmit(apdu);

    if (!response.success)
    {
        return false;
    }

    // Passo 2: autentica il blocco target del settore
    const uint8_t key_type_byte = (keyType == 'B') ? KEY_TYPE_B : KEY_TYPE_A;

    apdu = { 0xFF, 0x86, 0x00, 0x00, 0x05, 0x01, 0x00, static_cast<uint8_t>(toAbsBlock(sector, 0)), key_type_byte, 0x00 };
    response = m_reader.transmit(apdu);

    if (response.success)
    {
        auto& auth_state = m_authState[sector];
        auth_state.valid = true;
        auth_state.keyType = keyType;
        auth_state.key = key;
        
        if (keyType == 'A') 
            auth_state.keyA = key;
        else                
            auth_state.keyB = key;
    }
    
    return response.success;
}

bool MifareClassic::tryAuthenticate(int sector, const std::vector<MifareKey>& keys)
{
    constexpr std::array<char, 2> key_types = {'A', 'B'};
    
    for (const char kt : key_types)
    {
        for (const auto& key : keys)
        {
            if (authenticate(sector, key, kt))
                return true;
        }
    }

    return false;
}

bool MifareClassic::reAuth(int sector)
{
    const auto& auth = m_authState[sector];
    if (!auth.valid && !auth.hasKeyA() && !auth.hasKeyB()) 
        return false;

    Logger::debug("Reauthenticating sector " + std::to_string(sector) + " with Key" + auth.keyType + "...");

    // 1. Prova il tipo/chiave attivo
    if (authenticate(sector, auth.key, auth.keyType))
        return true;

    // 2. Fallback all'altro tipo memorizzato
    if (auth.keyType == 'A' && auth.hasKeyB())
    {
        Logger::debug("reAuth S" + std::to_string(sector) + ": KeyA failed, trying stored KeyB");
        return authenticate(sector, auth.keyB, 'B');
    }
    
    if (auth.keyType == 'B' && auth.hasKeyA())
    {
        Logger::debug("reAuth S" + std::to_string(sector) + ": KeyB failed, trying stored KeyA");
        return authenticate(sector, auth.keyA, 'A');
    }

    return false;
}

bool MifareClassic::isAuthenticated(int sector) const
{
    return (sector >= 0 && sector < SECTORS) && m_authState[sector].valid;
}

const SectorAuth& MifareClassic::getSectorAuth(int sector) const
{
    static const SectorAuth s_empty_auth{};
    if (sector < 0 || sector >= SECTORS) 
        return s_empty_auth;
    return m_authState[sector];
}

// TODO: aggiungere la possibilitá di leggere usando chiave A o B, parametro -t A|B
APDUResponse MifareClassic::readBlock(int sector, int relBlock)
{
    const uint8_t abs_block = static_cast<uint8_t>(toAbsBlock(sector, relBlock));

    std::vector<uint8_t> apdu = { 0xFF, 0xB0, 0x00, abs_block, 0x10 };
    auto response = m_reader.transmit(apdu);

    const bool needs_reauth = !response.success &&
        ((response.sw1 == 0x69 && response.sw2 == 0x82) ||
         (response.sw1 == 0x63 && response.sw2 == 0x00));

    if (needs_reauth && reAuth(sector))
    {
        response = m_reader.transmit(apdu);
    }

    return response;
}
