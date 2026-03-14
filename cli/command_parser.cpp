/**
 * @file command_parser.cpp
 * @brief Implementazione della shell interattiva e dei command handler di mftool.
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
#include "command_parser.h"
#include "../utils/atr_parser.h"
#include "../utils/hex.h"
#include "../mifare/access_bits.h"
#include "../mifare/block_type.h"
#include "../mifare/value_block.h"
#include <iostream>
#include <sstream>
#include <fstream>
#include <filesystem>
#include <iomanip>
#include <cctype>
#include <ctime>


namespace Color {
    constexpr const char* RESET       = "\033[0m";
    constexpr const char* BOLD        = "\033[1m";
    
    // Chiavi
    constexpr const char* KEY_A       = "\033[92m";  // Verde chiaro
    constexpr const char* KEY_B       = "\033[32m";  // Verde scuro
    
    // Access Bits
    constexpr const char* ACCESS_BITS = "\033[38;5;208m";  // Arancione
    
    // Blocchi
    constexpr const char* VALUE_BLOCK = "\033[33m";  // Giallo scuro
    constexpr const char* DATA_BLOCK  = "\033[0m";   // Nessun colore
    
    // Manufacturer Block
    constexpr const char* UID         = "\033[96m";  // Ciano
    constexpr const char* MFR_DATA    = "\033[95m";  // Magenta/Fucsia
    
    // Dettagli (grigio chiaro per info secondarie)
    constexpr const char* GRAY        = "\033[90m";
}

CommandParser::CommandParser()  = default;

CommandParser::~CommandParser() = default;

void CommandParser::showHelp() const
{
    using namespace Color;
    std::cout << "\n" << BOLD << "================ MFTOOL COMMANDS ================" << RESET << "\n";
    std::cout << "  connect\n";
    std::cout << "      Attempts tag connection, 5s timeout\n\n";
    std::cout << "  send <APDU hex>\n";
    std::cout << "      Sends a custom APDU command to the tag\n";
    std::cout << "      Ex: send FF CA 00 00 04\n\n";
    std::cout << "  scan [-k <keyfile>]\n";
    std::cout << "      Tries all 16 sectors with all keys (KeyA + KeyB)\n";
    std::cout << "      Default keyfile: keys/found.keys\n\n";
    std::cout << "  authenticate -s <sector> [-k <keyfile>] [-t A|B] [-key <6 bytes>]\n";
    std::cout << "      Authenticates a sector. Without -t tries KeyA then KeyB.\n\n";
    std::cout << "  read -s <sector> [-b <block>]\n";
    std::cout << "      Without -b: hex + ASCII + Access table for all 4 blocks\n";
    std::cout << "      With -b: detailed decode of a single block (0-3)\n\n";
    std::cout << "  dump\n";
    std::cout << "      Reads all 64 blocks (16 sectors) and saves to dumps/<UID>.mfd\n";
    std::cout << "      Format: MIFARE binary dump (1024 bytes, universal standard)\n";
    std::cout << "      Requires prior scan for authentication\n\n";
    std::cout << "  readdump <filename>\n";
    std::cout << "      Reads and displays a .mfd or .mct dump file from the dumps/ folder\n";
    std::cout << "      Supported formats: .mfd (1024 binary bytes), .mct (MCT text)\n";
    std::cout << "      Shows content with Access Bits and Value Blocks decoding\n";
    std::cout << "      Ex: readdump dump_3A165647.mfd\n";
    std::cout << "      Ex: readdump dump_510c.mct\n\n";
    std::cout << "  write -s <sector> -b <block> -v <32 hex chars>\n";
    std::cout << "      Writes 16 bytes to a block (requires prior authentication)\n";
    std::cout << "      B3 (sector trailer) requires explicit confirmation\n";
    std::cout << "      Ex: write -s 1 -b 0 -v 00112233445566778899AABBCCDDEEFF\n\n";
    std::cout << "  transfer -s <sector> -b <block> -v <value> -a <addr> -stg <S:B>\n";
    std::cout << "      Writes a Value Block via Restore+Transfer\n";
    std::cout << "      -v: signed decimal value (32-bit)\n";
    std::cout << "      -a: address byte in hex\n";
    std::cout << "      -stg: staging block (S:B) with write permission\n";
    std::cout << "            Same sector: ACR122U Restore Value Block (FF D7)\n";
    std::cout << "            Cross sector: PN532 RESTORE(C2) + TRANSFER(B0)\n";
    std::cout << "      Ex: transfer -s 3 -b 0 -v 100 -a 0D -stg 3:2\n";
    std::cout << "      Ex: transfer -s 3 -b 0 -v 100 -a 0D -stg 2:2\n\n";
    std::cout << "  clone <filename>\n";
    std::cout << "      Writes a dump file onto the present tag (block by block)\n";
    std::cout << "      Supported formats: .mfd (1024 binary bytes), .mct (MCT text)\n";
    std::cout << "      Skips identical blocks, uses Restore+Transfer for write-protected\n";
    std::cout << "      Value Blocks with DTR permission. Trailers written last.\n";
    std::cout << "      Requires prior scan for authentication\n";
    std::cout << "      Ex: clone dump_3A165647.mfd\n\n";
    std::cout << "  help    Show this message\n";
    std::cout << "  exit    Exit the program\n";
    std::cout << BOLD << "=================================================" << RESET << "\n\n";
}

bool CommandParser::initializeReader()
{
    try
    {
        m_reader = std::make_unique<PCSCReader>();
        m_reader->establishContext();

        auto readers = m_reader->listReaders();
        if (readers.empty())
        {
            std::cout << "[-] No readers found.\n";
            return false;
        }

        std::cout << "[+] Found " << readers.size() << " reader(s)\n";
        std::cout << "[+] Using reader: " << readers[0] << "\n";

        return true;
    }
    catch (const std::exception& e)
    {
        std::cout << "[-] Initialization failed: " << e.what() << "\n";
        return false;
    }
}

void CommandParser::cmdSendAPDU(std::istringstream& args)
{
    std::string tok;
    std::vector<uint8_t> apdu;

    try
    {
        while (args >> tok)
            apdu.emplace_back(static_cast<uint8_t>(std::stoul(tok, nullptr, 16)));
    }
    catch (const std::exception&)
    {
        std::cout << "[!] Invalid hex token: '" << tok << "'\n";
        std::cout << "    Ex: send FF CA 00 00 04\n";
        return;
    }

    if (apdu.empty())
    {
        std::cout << "[!] Usage: send <APDU hex>\n";
        return;
    }

    auto resp = m_reader->transmit(apdu);

    if (!resp.data.empty())
        std::cout << Hex::bytesToString(resp.data) << " ";

    std::cout << toHex(resp.sw1) << " " << toHex(resp.sw2);

    const std::string decoded = PCSCReader::decodeSW(resp.sw1, resp.sw2);
    if (!decoded.empty())
        std::cout << "  " << decoded;

    std::cout << "\n";
}

void CommandParser::cmdAuthenticate(std::istringstream& args)
{
    using namespace Color;

    int         sector = -1;
    std::string key_file = "keys/found.keys";
    char        key_type = '\0';
    std::string inline_key;

    std::string token;
    while (args >> token)
    {
        try
        {
            if      (token == "-s" && args >> token) sector    = std::stoi(token);
            else if (token == "-k" && args >> token) key_file  = token;
            else if (token == "-t" && args >> token) key_type  = (char)std::toupper(token[0]);
            else if (token == "-key" && args >> token) inline_key = token;
        }
        catch (const std::exception&)
        {
            std::cout << "[!] Invalid argument: '" << token << "'\n";
            std::cout << "[!] Usage: authenticate -s <sector 0-15> [-k <keyfile>] [-t A|B] [-key <6 bytes>]\n";
            return;
        }
    }

    if (sector < 0 || sector > 15)
    {
        std::cout << "[!] Usage: authenticate -s <sector 0-15> [-k <keyfile>] [-t A|B] [-key <6 bytes>]\n";
        return;
    }

    std::vector<MifareKey> keys;

    if (!inline_key.empty())
    {
        try
        {
            MifareKey key = Hex::stringToBytes(inline_key);
            keys.emplace_back(key);
        }
        catch (const std::invalid_argument& e)
        {
            std::cout << "[!] Invalid hex key: " << e.what() << "\n";
            return;
        }
    }
    else
    {
        keys = MifareClassic::loadKeys(key_file);
        if (keys.empty())
        {
            std::cout << "[!] No valid keys in: " << key_file << "\n";
            return;
        }
    }

    bool ok = false;

    if (key_type == '\0')
    {
        ok = m_mifare->tryAuthenticate(sector, keys);
    }
    else
    {
        for (const auto& key : keys)
        {
            if (m_mifare->authenticate(sector, key, key_type))
            {
                ok = true;
                break;
            }
        }
    }

    if (ok)
    {
        const auto& auth = m_mifare->getSectorAuth(sector);
        const char* key_color = (auth.keyType == 'A') ? KEY_A : KEY_B;

        std::cout << "[+] Sector " << sector
            << " authenticated (" << key_color << "Key" << auth.keyType << RESET << "): "
            << key_color << Hex::bytesToString(auth.key) << RESET << "\n";
    }
    else
    {
        std::cout << "[-] Authentication failed for sector " << sector
            << " with " << keys.size() << " key(s).\n";
    }
}

void CommandParser::cmdScan(std::istringstream& args)
{
    using namespace Color;
    
    std::string key_file = "keys/found.keys";
    std::string tok;
    while (args >> tok)
        if (tok == "-k" && args >> tok) key_file = tok;

    auto keys = MifareClassic::loadKeys(key_file);
    if (keys.empty())
    {
        std::cout << "[!] No valid keys in: " << key_file << "\n";
        return;
    }

    constexpr size_t KEY_W = 17;

    auto secStr = [](int s) {
        std::ostringstream ss;
        ss << std::dec << std::setw(2) << std::setfill('0') << s;
        return ss.str();
    };

    auto pad = [](const std::string& s, size_t w) {
        return s.size() < w ? s + std::string(w - s.size(), ' ') : s;
    };

    const std::string separator = " -----+-" + std::string(KEY_W, '-') + "-+-"
                              + std::string(KEY_W, '-');

    std::cout << "\nScanning " << MifareClassic::SECTORS
              << " sectors with " << keys.size() << " key(s) (KeyA + KeyB)...\n\n";

    std::cout << BOLD
              << "  Sec | " << pad("KeyA", KEY_W) << " | KeyB\n"
              << separator << "\n"
              << RESET;

    int cracked_A = 0, cracked_B = 0;

    for (int s = 0; s < MifareClassic::SECTORS; ++s)
    {
        std::string keyA_str, keyB_str;

        for (const auto& key : keys)
            if (m_mifare->authenticate(s, key, 'A'))
                { keyA_str = Hex::bytesToString(key); cracked_A++; break; }

        for (const auto& key : keys)
            if (m_mifare->authenticate(s, key, 'B'))
                { keyB_str = Hex::bytesToString(key); cracked_B++; break; }

        // Ripristina KeyA come autenticazione principale
        if (!keyA_str.empty())
            m_mifare->authenticate(s, m_mifare->getSectorAuth(s).keyA, 'A');

        const bool hasA = !keyA_str.empty();
        const bool hasB = !keyB_str.empty();

        std::cout << "  S" << secStr(s) << " | ";
        std::cout << (hasA ? KEY_A : GRAY) << pad(hasA ? keyA_str : "----", KEY_W) << RESET;
        std::cout << " | ";
        std::cout << (hasB ? KEY_B : GRAY) << (hasB ? keyB_str : "----") << RESET;
        std::cout << "\n";
    }

    std::cout << BOLD << separator << "\n" << RESET;
    std::cout << "\n[+] Results: "
              << KEY_A << cracked_A << "/16" << RESET << " KeyA,  "
              << KEY_B << cracked_B << "/16" << RESET << " KeyB found.\n\n";
}

void CommandParser::cmdRead(std::istringstream& args)
{
    using namespace Color;

    int sector   = -1;
    int rel_block = -1;

    std::string token;
    while (args >> token)
    {
        try
        {
            if      (token == "-s" && args >> token) sector   = std::stoi(token);
            else if (token == "-b" && args >> token) rel_block = std::stoi(token);
        }
        catch (const std::exception&)
        {
            std::cout << "[!] Invalid argument: '" << token << "'\n";
            std::cout << "[!] Usage: read -s <sector 0-15> [-b <block 0-3>]\n";
            return;
        }
    }

    if (sector < 0 || sector > 15 || (rel_block != -1 && (rel_block < 0 || rel_block > 3)))
    {
        std::cout << "[!] Usage: read -s <sector 0-15> [-b <block 0-3>]\n";
        return;
    }

    if (!m_mifare->isAuthenticated(sector))
    {
        std::cout << "[-] Sector " << sector << " not authenticated. Run 'scan' or 'authenticate' first.\n";
        return;
    }

    // Helper: colore byte in base al tipo di blocco e posizione
    auto byteColor = [](BlockType t, int i) -> const char* {
        switch (t)
        {
            case BlockType::Manufacturer: return i < 4  ? UID        : MFR_DATA;
            case BlockType::Trailer:      return i < 6  ? KEY_A
                                               : i < 10 ? ACCESS_BITS : KEY_B;
            case BlockType::Value:        return (i < 4 || i >= 8) ? VALUE_BLOCK : GRAY;
            default:                      return DATA_BLOCK;
        }
    };

    // Modalità tabella: tutti i blocchi del settore
    if (rel_block == -1)
    {
        std::vector<APDUResponse> resps(MifareClassic::BLOCKS_PER_SECTOR);
        for (int b = 0; b < MifareClassic::BLOCKS_PER_SECTOR; ++b)
            resps[b] = m_mifare->readBlock(sector, b);

        // Decodifica access bits dal sector trailer (B3)
        AccessBits ab;
        if (resps[3].success && resps[3].data.size() == 16)
            ab = AccessBits::decode(resps[3].data);

        const auto& auth = m_mifare->getSectorAuth(sector);

        std::cout << "\n" << BOLD << "[Sector " << sector << "]" << RESET
                  << " " << KEY_A << "KeyA" << RESET << ": "
                  << KEY_A << Hex::bytesToString(auth.keyA) << KEY_B << "  "
			      << "KeyB" << RESET << ": " << KEY_B << Hex::bytesToString(auth.keyB) << RESET << "\n";
        std::cout << "  Blk  Abs  | 00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F | ASCII            | [C1C2C3] Access\n";
        std::cout << "  ---------   -----------------------------------------------    ----------------   ----------------\n";

        for (int b = 0; b < MifareClassic::BLOCKS_PER_SECTOR; ++b)
        {
            const int abs_block = MifareClassic::toAbsBlock(sector, b);
            const auto& resp = resps[b];

            std::cout << "  B" << b << "  [" << toHex(static_cast<uint8_t>(abs_block)) << "]  | ";

            if (!resp.success)
            {
                std::cout << "read failed: " << PCSCReader::decodeSW(resp.sw1, resp.sw2) << "\n";
                continue;
            }

            const auto& block_data = resp.data;
            const BlockType type = detectBlockType(sector, b, block_data);

            // Hex colorato
            for (int i = 0; i < 16; ++i)
            {
                if (i == 8) std::cout << " ";
                std::cout << byteColor(type, i) << toHex(block_data[i]) << RESET << " ";
            }

            // ASCII
            std::cout << "| ";
            for (uint8_t byte : block_data)
                std::cout << (std::isprint(byte) ? (char)byte : '.');

            // Colonna access
            std::cout << " | ";
            if (type == BlockType::Manufacturer)
            {
                std::cout << "[mfr] read-only";
            }
            else if (!ab.valid)
            {
                std::cout << "INVALID acc bits!";
            }
            else
            {
                const char* desc = (type == BlockType::Trailer)
                    ? AccessBits::trailerDescShort(ab.idx[b])
                    : AccessBits::dataDescShort(ab.idx[b]);
                std::cout << GRAY << "[" << (int)ab.c1[b] << (int)ab.c2[b] << (int)ab.c3[b] << "] " << RESET << desc;
            }

            std::cout << "\n";
        }
        std::cout << "\n";
        return;
    }

    // Modalità dettaglio: singolo blocco 
    auto resp = m_mifare->readBlock(sector, rel_block);
    if (!resp.success)
    {
        std::cout << "[-] Read failed. " << PCSCReader::decodeSW(resp.sw1, resp.sw2) << "\n";
        return;
    }

    const auto& block_data = resp.data;
    const int abs_block = MifareClassic::toAbsBlock(sector, rel_block);
    const BlockType type = detectBlockType(sector, rel_block, block_data);

    // Intestazione
    std::cout << "[+] S" << sector << "/B" << rel_block
              << "  abs=" << abs_block << "  "
              << BOLD << "[" << blockTypeLabel(type) << "]" << RESET << "\n";

    // Riga hex colorata per gruppi
    auto printGroup = [&](int from, int to, const char* color) {
        for (int i = from; i <= to; ++i)
        {
            std::cout << color << toHex(block_data[i]) << RESET;
            if (i < to) std::cout << " ";
        }
    };

    std::cout << "    ";
    switch (type)
    {
        case BlockType::Manufacturer:
            printGroup(0,  3,  UID);         std::cout << "  ";
            printGroup(4,  15, MFR_DATA);
            break;
        case BlockType::Trailer:
            printGroup(0,  5,  KEY_A);       std::cout << "  ";
            printGroup(6,  9,  ACCESS_BITS); std::cout << "  ";
            printGroup(10, 15, KEY_B);
            break;
        case BlockType::Value:
            printGroup(0,  3,  VALUE_BLOCK); std::cout << "  ";
            printGroup(4,  7,  GRAY);        std::cout << "  ";
            printGroup(8,  11, VALUE_BLOCK); std::cout << "  ";
            printGroup(12, 15, VALUE_BLOCK);
            break;
        default:
            printGroup(0,  7,  DATA_BLOCK);  std::cout << "  ";
            printGroup(8,  15, DATA_BLOCK);
            break;
    }
    std::cout << "\n";

    // Dettagli campi in base al tipo di blocco
    switch (type)
    {
        case BlockType::Manufacturer:
        {
            std::cout << "    " << UID      << "UID    " << RESET << ": " << UID;
            for (int i = 0;  i < 4;  ++i) std::cout << toHex(block_data[i]) << (i <  3 ? " " : "");
            std::cout << RESET << "\n";

            std::cout << "    " << MFR_DATA << "Mfr Data" << RESET << ": " << MFR_DATA;
            for (int i = 4;  i < 16; ++i) std::cout << toHex(block_data[i]) << (i < 15 ? " " : "");
            std::cout << RESET << "\n";
            break;
        }
        case BlockType::Trailer:
        {            
            std::cout << "    " << ACCESS_BITS << "AccBits " << RESET << ": " << ACCESS_BITS
                << toHex(block_data[6]) << " " << toHex(block_data[7]) << " " << toHex(block_data[8]) << RESET << "\n";
            std::cout << "    " << "UserByte: " << toHex(block_data[9]) << "\n";
            break;
        }
        case BlockType::Value:
        {
            const int32_t val = static_cast<int32_t>(
                block_data[0] | (block_data[1] << 8) | (block_data[2] << 16) | (block_data[3] << 24));

            const std::string hexVal = "0x" + toHex(block_data[3]) + toHex(block_data[2])
                                   + toHex(block_data[1]) + toHex(block_data[0]);

            std::cout << "    " << VALUE_BLOCK << "Value   " << RESET << ": "
                      << VALUE_BLOCK << std::dec << val << RESET
                      << "  " << GRAY << hexVal << RESET << "\n";
            std::cout << "    " << VALUE_BLOCK << "Address " << RESET << ": "
                      << VALUE_BLOCK << std::dec << static_cast<int>(block_data[12]) << RESET
                      << "  " << GRAY << "0x" << toHex(block_data[12]) << RESET << "\n";
            break;
        }
        default: break;
    }
}

void CommandParser::cmdWrite(std::istringstream& args)
{
    using namespace Color;

    int         sector   = -1;
    int         rel_block = -1;
    std::string value_str;

    std::string token;
    while (args >> token)
    {
        try
        {
            if      (token == "-s" && args >> token) sector   = std::stoi(token);
            else if (token == "-b" && args >> token) rel_block = std::stoi(token);
            else if (token == "-v" && args >> token) value_str = token;
        }
        catch (const std::exception&)
        {
            std::cout << "[!] Invalid argument: '" << token << "'\n";
            std::cout << "[!] Usage: write -s <sector 0-15> -b <block 0-3> -v <32 hex chars>\n";
            return;
        }
    }

    if (sector < 0 || sector > 15 || rel_block < 0 || rel_block > 3 || value_str.empty())
    {
        std::cout << "[!] Usage: write -s <sector 0-15> -b <block 0-3> -v <32 hex chars>\n";
        std::cout << "    Ex: write -s 1 -b 0 -v 00112233445566778899AABBCCDDEEFF\n";
        return;
    }

    // Blocco manufacturer: rifiuto immediato
    if (sector == 0 && rel_block == 0)
    {
        std::cout << "[-] Cannot write Manufacturer Block (S0/B0).\n";
        return;
    }

    // Parsing del valore: 32 char hex -> 16 byte
    std::string cleaned;
    for (char c : value_str)
        if (!std::isspace(static_cast<unsigned char>(c)))
            cleaned += static_cast<char>(std::toupper(static_cast<unsigned char>(c)));

    if (cleaned.size() != 32)
    {
        std::cout << "[!] Value must be exactly 16 bytes (32 hex chars), got "
                  << cleaned.size() / 2 << " byte(s).\n";
        std::cout << "    Ex: -v 00112233445566778899AABBCCDDEEFF\n";
        return;
    }
    for (char c : cleaned)
    {
        if (!std::isxdigit(static_cast<unsigned char>(c)))
        {
            std::cout << "[!] Invalid hex character: '" << c << "'\n";
            return;
        }
    }

    std::vector<uint8_t> value(16);
    for (int i = 0; i < 16; ++i)
        value[i] = static_cast<uint8_t>(std::stoul(cleaned.substr(i * 2, 2), nullptr, 16));

    if (!m_mifare->isAuthenticated(sector))
    {
        std::cout << "[-] Sector " << sector << " not authenticated. Run 'scan' or 'authenticate' first.\n";
        return;
    }

    // Sector trailer: validazione access bits + conferma esplicita
    if (rel_block == 3)
    {
        // Verifica che i byte 6-8 del payload siano access bits internamente consistenti.
        // Access bits inconsistenti scritti su B3 bloccano il settore in modo permanente.
        const AccessBits ab = AccessBits::decode(value);
        if (!ab.valid)
        {
            std::cout << "[-] REFUSED: Access bits in bytes 6-8 ("
                      << toHex(value[6]) << " "
                      << toHex(value[7]) << " "
                      << toHex(value[8])
                      << ") are INVALID (nibble complement check failed).\n";
            std::cout << "    Writing invalid access bits permanently locks the sector.\n";
            return;
        }

        std::cout << "[!] WARNING: Writing Sector Trailer (B3).\n";
        std::cout << "    AccBits: " << ACCESS_BITS
                  << toHex(value[6]) << " "
                  << toHex(value[7]) << " "
                  << toHex(value[8])
                  << RESET << "  (consistent)\n";
        std::cout << "    Type Y to confirm: ";
        std::string confirm;
        std::getline(std::cin, confirm);
        if (confirm != "Y")
        {
            std::cout << "[-] Write cancelled.\n";
            return;
        }
    }

    // Esecuzione
    const int abs_block = MifareClassic::toAbsBlock(sector, rel_block);

    std::cout << "Writing S" << sector << "/B" << rel_block
              << "  abs=0x" << toHex(static_cast<uint8_t>(abs_block))
              << "...\n";

    const auto resp = m_mifare->writeBlock(sector, rel_block, value);

    if (resp.success)
        std::cout << "[+] Write OK  " << Hex::bytesToString(value) << "\n";
    else
        std::cout << "[-] Write failed: " << PCSCReader::decodeSW(resp.sw1, resp.sw2) << "\n";
}

void CommandParser::cmdTransfer(std::istringstream& args)
{
    using namespace Color;

    int         sector    = -1;
    int         rel_block = -1;
    std::string value_str;
    std::string addr_str;
    std::string stg_str;

    std::string token;
    while (args >> token)
    {
        try
        {
            if      (token == "-s"   && args >> token) sector    = std::stoi(token);
            else if (token == "-b"   && args >> token) rel_block = std::stoi(token);
            else if (token == "-v"   && args >> token) value_str = token;
            else if (token == "-a"   && args >> token) addr_str  = token;
            else if (token == "-stg" && args >> token) stg_str   = token;
        }
        catch (const std::exception&)
        {
            std::cout << "[!] Invalid argument: '" << token << "'\n";
            std::cout << "[!] Usage: transfer -s <sector> -b <block> -v <value> -a <addr> -stg <S:B>\n";
            return;
        }
    }

    if (sector < 0 || sector > 15 || rel_block < 0 || rel_block > 2 || value_str.empty() || addr_str.empty() || stg_str.empty())
    {
        std::cout << "[!] Usage: transfer -s <sector 0-15> -b <block 0-2> -v <value> -a <addr hex> -stg <S:B>\n";
        std::cout << "    -v: signed decimal value (32-bit)\n";
        std::cout << "    -a: address byte in hex\n";
        std::cout << "    -stg: staging block (S:B) with write permission\n";
        std::cout << "    Ex: transfer -s 3 -b 0 -v 100 -a 0D -stg 3:2\n";
        return;
    }

    // Blocco manufacturer: rifiuto immediato
    if (sector == 0 && rel_block == 0)
    {
        std::cout << "[-] Cannot write Manufacturer Block (S0/B0).\n";
        return;
    }

    // Parsing del valore decimale (signed 32-bit)
    int32_t value;
    try
    {
        long long parsed = std::stoll(value_str);
        if (parsed < INT32_MIN || parsed > INT32_MAX)
        {
            std::cout << "[!] Value out of range (signed 32-bit): " << value_str << "\n";
            return;
        }
        value = static_cast<int32_t>(parsed);
    }
    catch (const std::exception&)
    {
        std::cout << "[!] Invalid decimal value: '" << value_str << "'\n";
        return;
    }

    // Parsing dell'indirizzo
    uint8_t address;
    try
    {
        unsigned long parsed = std::stoul(addr_str, nullptr, 16);
        if (parsed > 0xFF)
        {
            std::cout << "[!] Address must be a single byte (00-FF): " << addr_str << "\n";
            return;
        }
        address = static_cast<uint8_t>(parsed);
    }
    catch (const std::exception&)
    {
        std::cout << "[!] Invalid hex address: '" << addr_str << "'\n";
        return;
    }

    // Formatta il Value Block MIFARE (16 byte ridondanti)
    const auto vb = ValueBlock::create(value, address);
    const std::vector<uint8_t> vb_data(vb.begin(), vb.end());

    std::cout << "\n" << BOLD << "[Value Block]" << RESET << "\n"
              << ValueBlock::summary(value, address) << "\n";

    // Parsing dello staging block (-stg S:B)
    int stg_sector = -1, stg_block = -1;

    const auto sep = stg_str.find(':');
    if (sep == std::string::npos)
    {
        std::cout << "[!] Invalid -stg format. Use S:B (es. 2:2)\n";
        return;
    }

    try
    {
        stg_sector = std::stoi(stg_str.substr(0, sep));
        stg_block  = std::stoi(stg_str.substr(sep + 1));
    }
    catch (const std::exception&)
    {
        std::cout << "[!] Invalid -stg format: '" << stg_str << "'. Use S:B (es. 2:2)\n";
        return;
    }

    if (stg_sector < 0 || stg_sector > 15 || stg_block < 0 || stg_block > 2)
    {
        std::cout << "[!] Staging block must be sector 0-15, block 0-2\n";
        return;
    }
    if (stg_sector == sector && stg_block == rel_block)
    {
        std::cout << "[!] Staging block cannot be the same as the destination\n";
        return;
    }
    if (stg_sector == 0 && stg_block == 0)
    {
        std::cout << "[-] Cannot use Manufacturer Block (S0/B0) as staging.\n";
        return;
    }

    if (!m_mifare->isAuthenticated(stg_sector))
    {
        std::cout << "[-] Staging sector " << stg_sector << " not authenticated.\n";
        return;
    }
    if (!m_mifare->isAuthenticated(sector))
    {
        std::cout << "[-] Destination sector " << sector << " not authenticated.\n";
        return;
    }

    const bool same_sector = (stg_sector == sector);

    // Route info
    std::cout << "\nS" << stg_sector << "/B" << stg_block
              << " (0x" << toHex(static_cast<uint8_t>(MifareClassic::toAbsBlock(stg_sector, stg_block)))
              << ") -> S" << sector << "/B" << rel_block
              << " (0x" << toHex(static_cast<uint8_t>(MifareClassic::toAbsBlock(sector, rel_block)))
              << ")";
    if (!same_sector)
        std::cout << "  " << GRAY << "(cross-sector via PN532)" << RESET;
    std::cout << "\n\n";

    if (same_sector)
    {
        // Same sector: ACR122U native Write + Restore Value Block
        std::cout << "Writing value to staging...\n";

        auto write_resp = m_mifare->writeBlock(stg_sector, stg_block, vb_data);
        if (!write_resp.success)
        {
            std::cout << "[-] Write to staging failed: "
                      << PCSCReader::decodeSW(write_resp.sw1, write_resp.sw2) << "\n\n";
            return;
        }
        std::cout << "[+] Staging write OK\n";

        std::cout << "Restore+Transfer...\n";

        auto rt_resp = m_mifare->restoreTransfer(stg_sector, stg_block, sector, rel_block);
        if (!rt_resp.success)
        {
            std::cout << "[-] Transfer failed: "
                      << (rt_resp.errorMessage.empty()
                          ? PCSCReader::decodeSW(rt_resp.sw1, rt_resp.sw2)
                          : rt_resp.errorMessage)
                      << "\n\n";
            return;
        }
        std::cout << "[+] Transfer OK\n";
    }
    else
    {
        // Cross sector: write -> PN532 restore -> re-auth -> PN532 transfer (pattern MCT)
        std::cout << "Restore+Transfer...\n";

        auto cs_resp = m_mifare->restoreTransfer(
            stg_sector, stg_block, sector, rel_block, vb_data);

        if (!cs_resp.success)
        {
            std::cout << "[-] Cross-sector transfer failed: "
                      << (cs_resp.errorMessage.empty()
                          ? PCSCReader::decodeSW(cs_resp.sw1, cs_resp.sw2)
                          : cs_resp.errorMessage)
                      << "\n\n";
            return;
        }
        std::cout << "[+] Transfer OK\n";
    }

    // Verifica
    std::cout << "Verifying...\n";

    auto verify_resp = m_mifare->readValue(sector, rel_block);
    if (verify_resp.success && verify_resp.data.size() == 4)
    {
        // ACR122U Read Value Block restituisce 4 byte MSB..LSB
        const int32_t read_val = static_cast<int32_t>(
            (verify_resp.data[0] << 24) | (verify_resp.data[1] << 16) |
            (verify_resp.data[2] << 8)  |  verify_resp.data[3]);

        if (read_val == value)
        {
            std::cout << "[+] Verified: value = " << VALUE_BLOCK << std::dec << read_val
                      << RESET << "\n\n";
        }
        else
        {
            std::cout << "[!] MISMATCH: expected " << std::dec << value
                      << ", read " << read_val << "\n\n";
        }
    }
    else
    {
        std::cout << "[!] Verify read failed: "
                  << PCSCReader::decodeSW(verify_resp.sw1, verify_resp.sw2) << "\n";
        std::cout << "    Transfer may have succeeded - use 'read -s " << sector
                  << " -b " << rel_block << "' to check manually.\n\n";
    }
}

void CommandParser::cmdDumpFile()
{
    for (int s = 0; s < MifareClassic::SECTORS; ++s)
    {
        if (!m_mifare->isAuthenticated(s))
        {
            std::cout << "[-] Sector " << s << " not authenticated. Run 'scan' first.\n";
            return;
        }
    }

    using namespace Color;

    std::string uid;

    auto resp = m_mifare->readBlock(0, 0);
    if (resp.success && resp.data.size() >= 4)
    {
        for (int i = 0; i < 4; ++i)
            uid += toHex(resp.data[i]);
    }

    if (uid.empty())
    {
        std::ostringstream ss;
        ss << "UNKNOWN_" << std::dec << static_cast<long>(std::time(nullptr));
        uid = ss.str();
    }

    try { std::filesystem::create_directories("dumps"); }
    catch (const std::exception& e)
    {
        std::cout << "[-] Cannot create dumps/ folder: " << e.what() << "\n";
        return;
    }

    const std::string filename = "dumps/dump_" + uid + ".mfd";

    struct BlockData { bool ok = false; std::vector<uint8_t> data; };
    std::vector<std::vector<BlockData>> mem(
        MifareClassic::SECTORS,
        std::vector<BlockData>(MifareClassic::BLOCKS_PER_SECTOR));

    int nOk = 0, nFail = 0;

    auto secStr = [](int s) -> std::string {
        std::ostringstream ss;
        ss << std::dec << std::setw(2) << std::setfill('0') << s;
        return ss.str();
    };

    std::cout << "\n" << BOLD << "Dumping " << MifareClassic::SECTORS
              << " sectors -> " << filename << RESET << "\n\n";

    for (int s = 0; s < MifareClassic::SECTORS; ++s)
    {
        int secOk = 0;
        for (int b = 0; b < MifareClassic::BLOCKS_PER_SECTOR; ++b)
        {
            auto resp = m_mifare->readBlock(s, b);
            mem[s][b].ok = resp.success;
            mem[s][b].data = resp.data;
            if (resp.success) { nOk++; secOk++; }
            else                nFail++;
        }
    }

    std::ofstream out(filename, std::ios::binary);
    if (!out)
    {
        std::cout << "[-] Cannot open " << filename << " for writing\n";
        return;
    }

    for (int s = 0; s < MifareClassic::SECTORS; ++s)
    {
        const auto& auth = m_mifare->getSectorAuth(s);

        for (int b = 0; b < MifareClassic::BLOCKS_PER_SECTOR; ++b)
        {
            const auto& cached_block = mem[s][b];

            // Inizializza a zero: blocchi non letti -> 16 byte 0x00
            std::vector<uint8_t> row(16, 0x00);
            if (cached_block.ok && cached_block.data.size() == 16)
                row = cached_block.data;

            // Iniezione chiavi nel sector trailer (blocco 3)
            // Iniettare le chiavi note produce un dump completo e reimportabile
            if (b == 3)
            {
                if (auth.keyA.size() == 6)
                    std::copy(auth.keyA.begin(), auth.keyA.end(), row.begin());
                if (auth.keyB.size() == 6)
                    std::copy(auth.keyB.begin(), auth.keyB.end(), row.begin() + 10);
            }

            out.write(reinterpret_cast<const char*>(row.data()), 16);
        }
    }

    std::cout << "\n[+] Saved: " << filename << "\n";
    std::cout << "    Format: MIFARE dump (.mfd) - 1024 binary bytes\n";
    std::cout << "    Blocks read: " << nOk << "/64"
              << "  Unread: " << nFail << "\n\n";
}

void CommandParser::cmdReadDump(std::istringstream& args)
{
    using namespace Color;

    std::string filename;
    if (!(args >> filename))
    {
        std::cout << "[!] Usage: readdump <filename>\n";
        std::cout << "    Ex: readdump dump_3A165647.mfd\n";
        std::cout << "    Ex: readdump dump_510c.mct\n";
        return;
    }

    // Prefisso "dumps/" se non già presente
    std::string file_path = filename;
    if (filename.find("dumps/") == std::string::npos)
        file_path = "dumps/" + filename;

    // Verifica esistenza file
    if (!std::filesystem::exists(file_path))
    {
        std::cout << "[-] File not found: " << file_path << "\n";
        return;
    }

    // Determina formato dal file extension
    const std::string ext = std::filesystem::path(file_path).extension().string();

    std::vector<uint8_t> data;

    if (ext == ".mct")
    {
        // Formato MCT: righe "+Sector: N" seguite da 4 righe di 32 caratteri hex
        std::ifstream file(file_path);
        if (!file)
        {
            std::cout << "[-] Cannot open: " << file_path << "\n";
            return;
        }

        std::string line;
        while (std::getline(file, line))
        {
            // Ignora righe vuote e header di settore
            if (line.empty() || line[0] == '+')
                continue;

            // Rimuovi eventuali \r
            if (!line.empty() && line.back() == '\r')
                line.pop_back();

            if (line.size() != 32)
            {
                std::cout << "[-] Invalid MCT line (expected 32 hex chars): " << line << "\n";
                return;
            }

            for (size_t i = 0; i < 32; i += 2)
            {
                if (!std::isxdigit(static_cast<unsigned char>(line[i])) ||
                    !std::isxdigit(static_cast<unsigned char>(line[i + 1])))
                {
                    std::cout << "[-] Invalid hex in MCT line: " << line << "\n";
                    return;
                }
                data.push_back(static_cast<uint8_t>(std::stoul(line.substr(i, 2), nullptr, 16)));
            }
        }

        if (data.size() != 1024)
        {
            std::cout << "[-] Invalid MCT file: expected 1024 bytes (64 blocks), got "
                      << data.size() << "\n";
            return;
        }
    }
    else
    {
        // Formato MFD: 1024 byte binari
        std::ifstream file(file_path, std::ios::binary);
        if (!file)
        {
            std::cout << "[-] Cannot open: " << file_path << "\n";
            return;
        }

        data.resize(1024);
        file.read(reinterpret_cast<char*>(data.data()), 1024);
        auto bytes_read = file.gcount();
        file.close();

        if (bytes_read != 1024)
        {
            std::cout << "[-] Invalid MFD file: expected 1024 bytes, got " << bytes_read << "\n";
            return;
        }
    }

    // Decodifica per ogni settore
    for (int s = 0; s < MifareClassic::SECTORS; ++s)
    {
        const int base_offset    = s * MifareClassic::BLOCKS_PER_SECTOR * 16;
        const int trailer_offset = base_offset + (3 * 16);

        // Decodifica access bits dal sector trailer del dump
        const std::vector<uint8_t> trailer_bytes(
            data.begin() + trailer_offset,
            data.begin() + trailer_offset + 16);
        const AccessBits ab = AccessBits::decode(trailer_bytes);

        std::cout << BOLD << "[Sector " << s << "]" << RESET << "\n";
        std::cout << "  Blk  Abs | 00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F | ASCII            | [C1C2C3] Access\n";
        std::cout << "  --------   ------------------------------------------------   ----------------   ----------------\n";

        for (int block = 0; block < MifareClassic::BLOCKS_PER_SECTOR; ++block)
        {
            const int abs_block    = MifareClassic::toAbsBlock(s, block);
            const int block_offset = base_offset + (block * 16);

            std::cout << "  B" << block << " [" << toHex(static_cast<uint8_t>(abs_block)) << "]  | ";

            // Estrai i 16 byte del blocco per il rilevamento del tipo
            const std::vector<uint8_t> block_data(
                data.begin() + block_offset,
                data.begin() + block_offset + 16);
            const BlockType type = detectBlockType(s, block, block_data);

            auto byteColor = [&](int i) -> const char* {
                switch (type)
                {
                    case BlockType::Manufacturer: return i < 4 ? UID : MFR_DATA;
                    case BlockType::Trailer:      return i < 6 ? KEY_A : (i < 10 ? ACCESS_BITS : KEY_B);
                    case BlockType::Value:        return (i < 4 || i >= 8) ? VALUE_BLOCK : GRAY;
                    default:                      return DATA_BLOCK;
                }
            };

            // Hex colorato
            for (int i = 0; i < 16; ++i)
            {
                if (i == 8) std::cout << " ";
                std::cout << byteColor(i) << toHex(data[block_offset + i]) << RESET << " ";
            }

            // ASCII
            std::cout << "| ";
            for (int i = 0; i < 16; ++i)
            {
                uint8_t byte = data[block_offset + i];
                std::cout << (std::isprint(byte) ? (char)byte : '.');
            }

            // Colonna Access
            std::cout << " | ";
            if (type == BlockType::Manufacturer)
            {
                std::cout << "[mfr] read-only";
            }
            else if (!ab.valid)
            {
                std::cout << "INVALID acc bits!";
            }
            else
            {
                const char* desc = (type == BlockType::Trailer)
                    ? AccessBits::trailerDescShort(ab.idx[block])
                    : AccessBits::dataDescShort(ab.idx[block]);
                std::cout << GRAY << "[" << (int)ab.c1[block] << (int)ab.c2[block] << (int)ab.c3[block] << "] " << RESET << desc;
            }

            std::cout << "\n";
        }
        std::cout << "\n";
    }
}

void CommandParser::cmdClone(std::istringstream& args)
{
	using namespace Color;

	std::string filename;
	if (!(args >> filename))
	{
		std::cout << "[!] Usage: clone <filename>\n";
		std::cout << "    Ex: clone dump_3A165647.mfd\n";
		return;
	}

	// Prefisso "dumps/" se non già presente
	std::string file_path = filename;
	if (filename.find("dumps/") == std::string::npos)
		file_path = "dumps/" + filename;

	if (!std::filesystem::exists(file_path))
	{
		std::cout << "[-] File not found: " << file_path << "\n";
		return;
	}

	// --- Caricamento dump ---
	const std::string ext = std::filesystem::path(file_path).extension().string();

	std::vector<uint8_t> data;

	if (ext == ".mct")
	{
		std::ifstream file(file_path);
		if (!file)
		{
			std::cout << "[-] Cannot open: " << file_path << "\n";
			return;
		}

		std::string line;
		while (std::getline(file, line))
		{
			if (line.empty() || line[0] == '+')
				continue;
			if (!line.empty() && line.back() == '\r')
				line.pop_back();

			if (line.size() != 32)
			{
				std::cout << "[-] Invalid MCT line (expected 32 hex chars): " << line << "\n";
				return;
			}

			for (size_t i = 0; i < 32; i += 2)
			{
				if (!std::isxdigit(static_cast<unsigned char>(line[i])) ||
					!std::isxdigit(static_cast<unsigned char>(line[i + 1])))
				{
					std::cout << "[-] Invalid hex in MCT line: " << line << "\n";
					return;
				}
				data.push_back(static_cast<uint8_t>(std::stoul(line.substr(i, 2), nullptr, 16)));
			}
		}

		if (data.size() != 1024)
		{
			std::cout << "[-] Invalid MCT file: expected 1024 bytes (64 blocks), got "
					  << data.size() << "\n";
			return;
		}
	}
	else
	{
		std::ifstream file(file_path, std::ios::binary);
		if (!file)
		{
			std::cout << "[-] Cannot open: " << file_path << "\n";
			return;
		}

		data.resize(1024);
		file.read(reinterpret_cast<char*>(data.data()), 1024);
		auto bytes_read = file.gcount();
		file.close();

		if (bytes_read != 1024)
		{
			std::cout << "[-] Invalid MFD file: expected 1024 bytes, got " << bytes_read << "\n";
			return;
		}
	}

	// --- Verifica autenticazione ---
	for (int s = 0; s < MifareClassic::SECTORS; ++s)
	{
		if (!m_mifare->isAuthenticated(s))
		{
			std::cout << "[-] Sector " << s << " not authenticated. Run 'scan' first.\n";
			return;
		}
	}

	// --- Conferma ---
	std::cout << "\n" << BOLD << "[Clone]" << RESET << " " << file_path << " -> tag ("
			  << MifareClassic::TOTAL_BLOCKS << " blocks)\n";
	std::cout << "[!] This will OVERWRITE all writable blocks on the tag.\n";
	std::cout << "    Type Y to confirm: ";
	std::string confirm;
	std::getline(std::cin, confirm);
	if (confirm != "Y")
	{
		std::cout << "[-] Clone cancelled.\n";
		return;
	}

	// --- Lettura completa del tag per confronto ---
	std::cout << "\nReading tag...\n";

	struct TagBlock { bool ok = false; std::vector<uint8_t> data; };
	std::array<std::array<TagBlock, MifareClassic::BLOCKS_PER_SECTOR>, MifareClassic::SECTORS> tag{};

	for (int s = 0; s < MifareClassic::SECTORS; ++s)
	{
		for (int b = 0; b < MifareClassic::BLOCKS_PER_SECTOR; ++b)
		{
			auto resp = m_mifare->readBlock(s, b);
			tag[s][b] = { resp.success, std::move(resp.data) };
		}

		// Inietta le chiavi note nel trailer letto
		if (tag[s][3].ok && tag[s][3].data.size() == MifareClassic::BLOCK_SIZE)
		{
			const auto& auth = m_mifare->getSectorAuth(s);
			if (auth.hasKeyA())
				std::copy(auth.keyA.begin(), auth.keyA.end(), tag[s][3].data.begin());
			if (auth.hasKeyB())
				std::copy(auth.keyB.begin(), auth.keyB.end(), tag[s][3].data.begin() + 10);
		}
	}

	// --- Decodifica access bits del TAG (stato corrente, determina i permessi) ---
	std::array<AccessBits, MifareClassic::SECTORS> tag_ab{};
	for (int s = 0; s < MifareClassic::SECTORS; ++s)
		if (tag[s][3].ok && tag[s][3].data.size() == MifareClassic::BLOCK_SIZE)
			tag_ab[s] = AccessBits::decode(tag[s][3].data);

	// Decrement/Transfer/Restore disponibile per idx 0, 1, 6
	auto hasDTR = [](uint8_t idx) -> bool { return idx == 0 || idx == 1 || idx == 6; };

	// Validazione struttura Value Block (necessaria per RESTORE MIFARE)
	auto isValueBlock = [](const std::vector<uint8_t>& d) -> bool {
		if (d.size() != 16) return false;
		for (int i = 0; i < 4; ++i)
		{
			if (d[i] != d[i + 8])                              return false;
			if (d[i] != static_cast<uint8_t>(~d[i + 4]))       return false;
		}
		return d[12] == d[14] && d[12] == static_cast<uint8_t>(~d[13]);
	};

	// --- Ricerca staging block: serve Write + DTR (idx 0 o 6) ---
	int stg_s = -1, stg_b = -1;
	for (int s = 0; s < MifareClassic::SECTORS && stg_s < 0; ++s)
	{
		if (!tag_ab[s].valid) continue;
		for (int b = 0; b < 3; ++b)
		{
			if (s == 0 && b == 0) continue;
			const uint8_t idx = tag_ab[s].idx[b];
			if (idx == 0 || idx == 6)
			{
				stg_s = s;
				stg_b = b;
				break;
			}
		}
	}

	if (stg_s >= 0)
		std::cout << "[+] Staging block: S"
				  << std::setw(2) << std::setfill('0') << stg_s << "/B" << stg_b
				  << "  " << GRAY << "(restore+transfer fallback)" << RESET << "\n";

	int nWritten = 0, nSame = 0, nSkipped = 0, nFailed = 0;

	auto printPrefix = [&](int s, int b) {
		const int abs = MifareClassic::toAbsBlock(s, b);
		std::cout << "  [" << toHex(static_cast<uint8_t>(abs))
				  << "] S" << std::setw(2) << std::setfill('0') << s
				  << "/B" << b << "  ";
	};

	std::cout << "\n";

	for (int s = 0; s < MifareClassic::SECTORS; ++s)
	{
		for (int b = 0; b < MifareClassic::BLOCKS_PER_SECTOR; ++b)
		{
			const int abs_block = MifareClassic::toAbsBlock(s, b);
			const int offset    = abs_block * MifareClassic::BLOCK_SIZE;

			std::vector<uint8_t> dump_block(
				data.begin() + offset,
				data.begin() + offset + MifareClassic::BLOCK_SIZE);

			printPrefix(s, b);

			// Manufacturer block: skip
			if (s == 0 && b == 0)
			{
				std::cout << GRAY << "SKIP" << RESET << "  manufacturer\n";
				nSkipped++;
				continue;
			}

			// Sector trailer: validazione access bits nel dump
			if (b == 3)
			{
				const AccessBits ab = AccessBits::decode(dump_block);
				if (!ab.valid)
				{
					std::cout << GRAY << "SKIP" << RESET << "  invalid AccBits "
							  << toHex(dump_block[6]) << " "
							  << toHex(dump_block[7]) << " "
							  << toHex(dump_block[8]) << "\n";
					nSkipped++;
					continue;
				}
			}

			// Confronto con tag: skip se identici
			if (tag[s][b].ok && tag[s][b].data == dump_block)
			{
				std::cout << GRAY << "SAME" << RESET << "\n";
				nSame++;
				continue;
			}

			// Tentativo di scrittura diretta
			auto resp = m_mifare->writeBlock(s, b, dump_block);
			if (resp.success)
			{
				std::cout << (b == 3 ? ACCESS_BITS : KEY_A) << "OK" << RESET << "\n";
				nWritten++;
				continue;
			}

			// Fallback: Restore+Transfer (solo data blocks con DTR + formato Value Block)
			if (b < 3 && stg_s >= 0 && tag_ab[s].valid
				&& hasDTR(tag_ab[s].idx[b]) && isValueBlock(dump_block))
			{
				auto rt = m_mifare->restoreTransfer(stg_s, stg_b, s, b, dump_block);
				if (rt.success)
				{
					std::cout << VALUE_BLOCK << "OK" << RESET << "  "
							  << GRAY << "(transfer via S"
							  << std::setw(2) << std::setfill('0') << stg_s
							  << "/B" << stg_b << ")" << RESET << "\n";
					nWritten++;
					continue;
				}
			}

			std::cout << "\033[91m" << "FAIL" << RESET << "  "
					  << PCSCReader::decodeSW(resp.sw1, resp.sw2) << "\n";
			nFailed++;
		}
	}

	// =================== Summary ===================
	std::cout << "\n[+] Clone complete: "
			  << KEY_A << nWritten << RESET << " written, "
			  << GRAY << nSame << RESET << " same, "
			  << GRAY << nSkipped << RESET << " skipped, "
			  << (nFailed > 0 ? "\033[91m" : GRAY) << nFailed << RESET << " failed\n\n";
}

void CommandParser::run()
{
    using namespace Color;

    if (!initializeReader())
        return;

    std::string selected_reader = m_reader->listReaders()[0];
    bool should_exit = false;
    bool tag_present = false;

    std::cout << "\n" << BOLD << "========== MFTOOL Interactive Shell ==========" << RESET << "\n";
    std::cout << "Type 'help' for commands, 'exit' to quit.\n";

    // Shell interattiva sempre attiva
    while (!should_exit)
    {
        // Prompt diverso in base alla presenza del tag
        if (tag_present)
            std::cout << BOLD << "[TAG]" << RESET << " > ";
        else
            std::cout << "> ";

        std::string line;
        std::getline(std::cin, line);

        std::istringstream iss(line);
        std::string cmd;
        iss >> cmd;

        // Comandi globali (non richiedono tag)
        if (cmd == "exit")
        {
            should_exit = true;
            continue;
        }
        else if (cmd == "help")
        {
            showHelp();
            continue;
        }
        else if (cmd == "readdump")
        {
            cmdReadDump(iss);
            continue;
        }
        else if (cmd == "connect")
        {
            std::cout << "Waiting for tag...\n";
            if (m_reader->waitAndConnect(selected_reader, 5))
            {
                m_mifare = std::make_unique<MifareClassic>(*m_reader);
                CardInfo info = m_reader->getCardInfo();

                std::cout << "\n[+] TAG DETECTED\n";
                std::cout << "    ATR:  " << Hex::bytesToString(info.atr) << "\n";
                std::cout << "    TYPE: " << ATRParser::getCardType(info.atr) << "\n";

                // UID: GET DATA (FF CA 00 00 04)
                auto resp = m_reader->transmit({ 0xFF, 0xCA, 0x00, 0x00, 0x04 });
                if (resp.success && resp.data.size() >= 4)
                    std::cout << "    UID:  " << Hex::bytesToString(resp.data) << "\n";
                else
                    std::cout << "    UID:  (read failed)\n";

                std::cout << "\n";
                tag_present = true;
            }
            else
            {
                std::cout << "[-] No tag detected (timeout)\n";
                tag_present = false;
            }
            continue;
        }

        // Se il tag non è presente e si é fatto un comando che lo richiede, avvisa
        if (!tag_present || !m_mifare)
        {
            if (cmd == "scan" || cmd == "read" || cmd == "send" ||
                cmd == "dump" || cmd == "write" || cmd == "transfer" || cmd == "authenticate" ||
                cmd == "clone")
            {
                std::cout << "[!] No tag present. Use 'connect' to detect a tag.\n";
                continue;
            }

            if (!cmd.empty())
            {
                std::cout << "[!] Unknown command. Type 'help'.\n";
            }
            continue;
        }

        // Controlla se il tag è ancora presente
        CardInfo currentInfo = m_reader->getCardInfo();
        if (currentInfo.cardState != "Present")
        {
            std::cout << "\n[-] Tag removed\n\n";
            m_reader->disconnect();
            m_mifare.reset();
            tag_present = false;
            continue;
        }

        // Comandi che richiedono il tag
        if      (cmd == "send") { cmdSendAPDU(iss); }
        else if (cmd == "scan") { cmdScan(iss); }
        else if (cmd == "authenticate") { cmdAuthenticate(iss); }
        else if (cmd == "read")  { cmdRead(iss); }
        else if (cmd == "write")  { cmdWrite(iss); }
        else if (cmd == "transfer") { cmdTransfer(iss); }
        else if (cmd == "dump")   { cmdDumpFile(); }
        else if (cmd == "clone") { cmdClone(iss); }
        else if (!cmd.empty())
        {
            std::cout << "[!] Unknown command. Type 'help'.\n";
        }
    }

    if (tag_present)
    {
        m_reader->disconnect();
    }
    m_reader->releaseContext();
    std::cout << "\n[+] Goodbye!\n";
}
