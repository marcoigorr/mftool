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

    Logger::debug("Reauthenticating sector " + std::to_string(sector) + " with stored Key" + auth.keyType + "...");

    // 1. Prova il tipo/chiave attivo
    if (authenticate(sector, auth.key, auth.keyType))
        return true;

    // 2. Fallback all'altro tipo memorizzato
    if (auth.keyType == 'A' && auth.hasKeyB())
    {
        Logger::debug("Reauthentication failed. Trying stored KeyB");
        return authenticate(sector, auth.keyB, 'B');
    }
    
    if (auth.keyType == 'B' && auth.hasKeyA())
    {
        Logger::debug("Reauthentication failed. Trying stored KeyA");
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

APDUResponse MifareClassic::writeBlock(int sector, int relBlock, const std::vector<uint8_t>& data)
{
    if (data.size() != static_cast<size_t>(BLOCK_SIZE))
    {
        APDUResponse err;
        err.errorMessage = "writeBlock: data must be exactly 16 bytes";
        return err;
    }

    const uint8_t abs_block = static_cast<uint8_t>(toAbsBlock(sector, relBlock));

    // UPDATE BINARY: FF D6 00 <abs_block> 10 <16 bytes>
    std::vector<uint8_t> apdu = { 0xFF, 0xD6, 0x00, abs_block, 0x10, 
        data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7], 
        data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15] };

    auto response = m_reader.transmit(apdu);

    const bool needs_reauth = !response.success &&
        ((response.sw1 == 0x69 && response.sw2 == 0x82) ||
         (response.sw1 == 0x63 && response.sw2 == 0x00));

    if (needs_reauth && reAuth(sector))
        response = m_reader.transmit(apdu);

    return response;
}

APDUResponse MifareClassic::readValue(int sector, int relBlock)
{
    const uint8_t abs_block = static_cast<uint8_t>(toAbsBlock(sector, relBlock));

    // ACR122U 5.5.2 Read Value Block: FF B1 00 <block> 04
    // Risposta: Value (4 byte MSB..LSB) + SW1 SW2
    std::vector<uint8_t> apdu = { 0xFF, 0xB1, 0x00, abs_block, 0x04 };
    auto response = m_reader.transmit(apdu);

    const bool needs_reauth = !response.success &&
        ((response.sw1 == 0x69 && response.sw2 == 0x82) ||
         (response.sw1 == 0x63 && response.sw2 == 0x00));

    if (needs_reauth && reAuth(sector))
        response = m_reader.transmit(apdu);

    return response;
}

APDUResponse MifareClassic::storeValue(int sector, int relBlock, int32_t value)
{
    const uint8_t abs_block = static_cast<uint8_t>(toAbsBlock(sector, relBlock));

    // ACR122U 5.5.1 Value Block Operation: FF D7 00 <block> 05 <VB_OP> <Value MSB..LSB>
    // VB_OP = 00h: Store - converte il blocco in formato Value Block
    std::vector<uint8_t> apdu = {
        0xFF, 0xD7, 0x00, abs_block, 0x05, 0x00,
        static_cast<uint8_t>((value >> 24) & 0xFF),
        static_cast<uint8_t>((value >> 16) & 0xFF),
        static_cast<uint8_t>((value >> 8) & 0xFF),
        static_cast<uint8_t>(value & 0xFF)
    };

    auto response = m_reader.transmit(apdu);

    const bool needs_reauth = !response.success &&
        ((response.sw1 == 0x69 && response.sw2 == 0x82) ||
         (response.sw1 == 0x63 && response.sw2 == 0x00));

    if (needs_reauth && reAuth(sector))
        response = m_reader.transmit(apdu);

    return response;
}

APDUResponse MifareClassic::restoreTransfer(int srcSector, int srcBlock, int dstSector, int dstBlock)
{
    // ACR122U 5.5.3: sorgente e destinazione devono essere nello stesso settore
    if (srcSector != dstSector)
    {
        APDUResponse err;
        err.errorMessage = "Restore Value Block requires same sector (ACR122U 5.5.3). "
                           "Source S" + std::to_string(srcSector) + " != Dest S" + std::to_string(dstSector);
        Logger::error(err.errorMessage);
        return err;
    }

    const uint8_t src_abs = static_cast<uint8_t>(toAbsBlock(srcSector, srcBlock));
    const uint8_t dst_abs = static_cast<uint8_t>(toAbsBlock(dstSector, dstBlock));

    Logger::debug("Restore Value Block: abs " + std::to_string(src_abs) + " -> " + std::to_string(dst_abs));

    // ACR122U 5.5.3 Restore Value Block: FF D7 00 <Source Block> 02 03 <Target Block>
    std::vector<uint8_t> apdu = { 0xFF, 0xD7, 0x00, src_abs, 0x02, 0x03, dst_abs };
    auto resp = m_reader.transmit(apdu);

    const bool needs_reauth = !resp.success &&
        ((resp.sw1 == 0x69 && resp.sw2 == 0x82) ||
         (resp.sw1 == 0x63 && resp.sw2 == 0x00));

    if (needs_reauth && reAuth(srcSector))
        resp = m_reader.transmit(apdu);

    return resp;
}

APDUResponse MifareClassic::pn532DataExchange(const std::vector<uint8_t>& mifareCmd)
{
    // ACR122U Escape APDU: FF 00 00 00 <Lc> D4 40 01 <mifare cmd bytes>
    // D4 = TFI host->PN532, 40 = InDataExchange, 01 = target number
    std::vector<uint8_t> apdu;
    apdu.reserve(5 + 3 + mifareCmd.size());

    const uint8_t lc = static_cast<uint8_t>(3 + mifareCmd.size());
    apdu.insert(apdu.end(), { 0xFF, 0x00, 0x00, 0x00, lc, 0xD4, 0x40, 0x01 });
    apdu.insert(apdu.end(), mifareCmd.begin(), mifareCmd.end());

    auto resp = m_reader.transmit(apdu);

    // Risposta PN532: D5 41 <status> [data]
    // Status 0x00 = successo
    APDUResponse result;
    result.sw1 = resp.sw1;
    result.sw2 = resp.sw2;
    result.data = resp.data;

    if (!resp.success || resp.data.size() < 3)
    {
        result.success = false;
        result.errorMessage = "PN532 InDataExchange failed";
        return result;
    }

    result.success = (resp.data[2] == 0x00);
    if (!result.success)
    {
        std::vector<uint8_t> status_byte = { resp.data[2] };
        result.errorMessage = "PN532 status: 0x" + Hex::bytesToString(status_byte);
    }

    return result;
}

APDUResponse MifareClassic::restoreTransfer(
    int stageSector, int stageBlock,
    int destSector, int destBlock,
    const std::vector<uint8_t>& valueBlock)
{
    const uint8_t stage_abs = static_cast<uint8_t>(toAbsBlock(stageSector, stageBlock));
    const uint8_t dest_abs   = static_cast<uint8_t>(toAbsBlock(destSector, destBlock));

    Logger::debug("Cross-sector transfer: stage abs " + std::to_string(stage_abs)
                + " -> dest abs " + std::to_string(dest_abs));

    // Fase 1: Auth staging sector + backup + write
    if (!reAuth(stageSector))
    {
        APDUResponse err;
        err.errorMessage = "Auth failed for staging sector " + std::to_string(stageSector);
        Logger::error(err.errorMessage);
        return err;
    }

    // Backup contenuto originale dello staging block (come MCT)
    auto backup_resp = readBlock(stageSector, stageBlock);
    std::vector<uint8_t> original_data;
    if (backup_resp.success && backup_resp.data.size() == BLOCK_SIZE)
        original_data = backup_resp.data;

    // Scrivi il value block preparato nello staging
    auto write_resp = writeBlock(stageSector, stageBlock, valueBlock);
    if (!write_resp.success)
    {
        write_resp.errorMessage = "Write to staging block failed";
        Logger::error(write_resp.errorMessage);
        return write_resp;
    }
    Logger::debug("Staging write OK");

    // Fase 2: RESTORE dallo staging (PN532 InDataExchange, MIFARE 0xC2)
    auto restore_resp = pn532DataExchange({ 0xC2, stage_abs });
    if (!restore_resp.success)
    {
        restore_resp.errorMessage = "RESTORE failed for abs block " + std::to_string(stage_abs);
        Logger::error(restore_resp.errorMessage);
        return restore_resp;
    }
    Logger::debug("RESTORE OK from abs " + std::to_string(stage_abs));

    // Fase 3: Re-auth settore destinazione
    if (!reAuth(destSector))
    {
        APDUResponse err;
        err.errorMessage = "Auth failed for destination sector " + std::to_string(destSector);
        Logger::error(err.errorMessage);
        return err;
    }

    // Fase 4: TRANSFER alla destinazione (PN532 InDataExchange, MIFARE 0xB0)
    auto transfer_resp = pn532DataExchange({ 0xB0, dest_abs });
    if (!transfer_resp.success)
    {
        transfer_resp.errorMessage = "TRANSFER failed for abs block " + std::to_string(dest_abs);
        Logger::error(transfer_resp.errorMessage);
        return transfer_resp;
    }
    Logger::debug("TRANSFER OK to abs " + std::to_string(dest_abs));

    // Fase 5: Ripristina contenuto originale dello staging block
    if (!original_data.empty())
    {
        if (stageSector != destSector)
        {
            if (!reAuth(stageSector))
                Logger::warning("Cannot re-auth staging sector for restore");
        }

        auto restore_orig_resp = writeBlock(stageSector, stageBlock, original_data);
        if (restore_orig_resp.success)
            Logger::debug("Staging block restored to original content");
        else
            Logger::warning("Failed to restore staging block original content");
    }

    return transfer_resp;
}
