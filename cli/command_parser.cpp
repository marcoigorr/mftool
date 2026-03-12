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
    std::cout << "      Reads and displays a .mfd dump file from the dumps/ folder\n";
    std::cout << "      Shows content with Access Bits and Value Blocks decoding\n";
    std::cout << "      Ex: readdump dump_3A165647.mfd\n\n";
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

    std::cout << std::uppercase << std::hex << std::setw(2) << std::setfill('0') << (int)resp.sw1
              << " " << std::setw(2) << std::setfill('0') << (int)resp.sw2;

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
    
    std::string keyFile = "keys/found.keys";
    std::string tok;
    while (args >> tok)
        if (tok == "-k" && args >> tok) keyFile = tok;

    auto keys = MifareClassic::loadKeys(keyFile);
    if (keys.empty())
    {
        std::cout << "[!] No valid keys in: " << keyFile << "\n";
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

    const std::string hRule = " -----+-" + std::string(KEY_W, '-') + "-+-"
                                          + std::string(KEY_W, '-');

    std::cout << "\nScanning " << MifareClassic::SECTORS
              << " sectors with " << keys.size() << " key(s) (KeyA + KeyB)...\n\n";

    std::cout << BOLD
              << "  Sec | " << pad("KeyA", KEY_W) << " | KeyB\n"
              << hRule << "\n"
              << RESET;

    int crackedA = 0, crackedB = 0;

    for (int s = 0; s < MifareClassic::SECTORS; ++s)
    {
        std::string keyAStr, keyBStr;

        for (const auto& key : keys)
            if (m_mifare->authenticate(s, key, 'A'))
                { keyAStr = Hex::bytesToString(key); crackedA++; break; }

        for (const auto& key : keys)
            if (m_mifare->authenticate(s, key, 'B'))
                { keyBStr = Hex::bytesToString(key); crackedB++; break; }

        // Ripristina KeyA come autenticazione principale
        if (!keyAStr.empty())
            m_mifare->authenticate(s, m_mifare->getSectorAuth(s).keyA, 'A');

        const bool hasA = !keyAStr.empty();
        const bool hasB = !keyBStr.empty();

        std::cout << "  S" << secStr(s) << " | ";
        std::cout << (hasA ? KEY_A : GRAY) << pad(hasA ? keyAStr : "----", KEY_W) << RESET;
        std::cout << " | ";
        std::cout << (hasB ? KEY_B : GRAY) << (hasB ? keyBStr : "----") << RESET;
        std::cout << "\n";
    }

    std::cout << BOLD << hRule << "\n" << RESET;
    std::cout << "\n[+] Results: "
              << KEY_A << crackedA << "/16" << RESET << " KeyA,  "
              << KEY_B << crackedB << "/16" << RESET << " KeyB found.\n\n";
}

// TODO: separa la stima di ACs bits in una funzione a parte, utilizzabile anche come comando (cmdCalculateAccessBits e cmdTranslateAccessBits).
//       Separare anche i vari formati dei blocchi in strutture dedicate.
void CommandParser::cmdRead(std::istringstream& args)
{
    using namespace Color;
    
    int sector   = -1;
    int relBlock = -1;

    std::string token;
    while (args >> token)
    {
        try
        {
            if      (token == "-s" && args >> token) sector   = std::stoi(token);
            else if (token == "-b" && args >> token) relBlock = std::stoi(token);
        }
        catch (const std::exception&)
        {
            std::cout << "[!] Invalid argument: '" << token << "'\n";
            std::cout << "[!] Usage: read -s <sector 0-15> [-b <block 0-3>]\n";
            return;
        }
    }

    if (sector < 0 || sector > 15 || (relBlock != -1 && (relBlock < 0 || relBlock > 3)))
    {
        std::cout << "[!] Usage: read -s <sector 0-15> [-b <block 0-3>]\n";
        return;
    }

    if (!m_mifare->isAuthenticated(sector))
    {
        std::cout << "[-] Sector " << sector << " not authenticated. Run 'scan' or 'authenticate' first.\n";
        return;
    }

    auto hx = [](uint8_t b) {
        std::ostringstream ss;
        ss << std::uppercase << std::hex << std::setw(2) << std::setfill('0') << (int)b;
        return ss.str();
    };

    // Modalità tabella
    if (relBlock == -1)
    {
        std::vector<APDUResponse> resps(MifareClassic::BLOCKS_PER_SECTOR);
        for (int b = 0; b < MifareClassic::BLOCKS_PER_SECTOR; ++b)
            resps[b] = m_mifare->readBlock(sector, b);

        // Decodifica access bits dal sector trailer (B3)
        uint8_t accC1[4]  = {}, accC2[4]  = {}, accC3[4]  = {}, accIdx[4] = {};
        bool trailerValid = false;

        if (resps[3].success && resps[3].data.size() == 16)
        {
            const auto& t = resps[3].data;
            trailerValid =
                ((t[6] & 0x0F) == ((~t[7] >> 4) & 0x0F)) &&
                ((t[6] >>  4)  == ((~t[8])       & 0x0F)) &&
                ((t[7] & 0x0F) == ((~t[8] >> 4)  & 0x0F));

            if (trailerValid)
            {
                for (int b = 0; b < 4; ++b)
                {
                    accC1[b]  = (t[7] >> (4 + b)) & 1;
                    accC2[b]  = (t[8] >>       b)  & 1;
                    accC3[b]  = (t[8] >> (4 + b)) & 1;
                    accIdx[b] = (accC1[b] << 2) | (accC2[b] << 1) | accC3[b];
                }
            }
        }

        static const char* dataAccShort[8] = {
            "r/w/inc/dec  KeyA|B",
            "r+dec  KeyA|B  (value NR)",
            "r  KeyA|B",
            "r/w  KeyB",
            "r:KeyA|B  w:KeyB",
            "r  KeyB",
            "r+dec:A|B  inc:B  (value)",
            "blocked"
        };
        static const char* trailAccShort[8] = {
            "KeyB readable",
            "transport  acc:A  keyB:rw-A",
            "acc-r:A  keyB-r:A",
            "w-KeyA:B  acc:B  keyB:B",
            "w-KeyA:B  acc-r:A|B  keyB:B",
            "acc:B",
            "write-protect  acc-r:A|B",
            "locked  acc-r:A|B"
        };

        const auto& auth = m_mifare->getSectorAuth(sector);
        const char* keyColor = (auth.keyType == 'A') ? KEY_A : KEY_B;
        
        std::cout << "\n" << BOLD << "[Sector " << sector << "]" << RESET
                  << " " << keyColor << "Key" << auth.keyType << RESET << ": "
                  << keyColor << Hex::bytesToString(auth.key) << RESET << "\n";
        std::cout << "  Blk  Abs  | 00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F | ASCII            | [CxN] Access\n";
        std::cout << "  ---------   -----------------------------------------------   ----------------   -------------\n";

        for (int b = 0; b < MifareClassic::BLOCKS_PER_SECTOR; ++b)
        {
            const int   absBlock = MifareClassic::toAbsBlock(sector, b);
            const auto& resp     = resps[b];

            std::cout << "  B" << b << " [" << hx(static_cast<uint8_t>(absBlock)) << "]  | ";

            if (!resp.success)
            {
                std::cout << "read failed: " << PCSCReader::decodeSW(resp.sw1, resp.sw2) << "\n";
                continue;
            }

            const auto& d = resp.data;

            const bool isMfr     = (sector == 0 && b == 0);
            const bool isTrailer = (b == 3);
            bool isValue = false;
            if (!isMfr && !isTrailer && d.size() == 16)
            {
                isValue = true;
                for (int i = 0; i < 4 && isValue; ++i)
                {
                    if (d[i] != d[i + 8])           isValue = false;
                    if (d[i] != (uint8_t)~d[i + 4]) isValue = false;
                }
                if (d[12] != d[14])            isValue = false;
                if (d[12] != (uint8_t)~d[13]) isValue = false;
            }

            auto byteColor = [&](int i) -> const char* {
                if (isMfr)     return i <  4 ? UID : MFR_DATA;
                if (isTrailer) return i <  6 ? KEY_A : i < 10 ? ACCESS_BITS : KEY_B;
                if (isValue)   return i <  4 ? VALUE_BLOCK : i <  8 ? GRAY : i < 12 ? VALUE_BLOCK : VALUE_BLOCK;
                return DATA_BLOCK;
            };

            for (int i = 0; i < 16; ++i)
            {
                if (i == 8) std::cout << " ";
                std::cout << byteColor(i) << hx(d[i]) << RESET << " ";
            }

            std::cout << "| ";
            for (uint8_t byte : d)
                std::cout << (std::isprint(byte) ? (char)byte : '.');

            std::cout << " | ";
            if (isMfr)
            {
                std::cout << "[mfr] read-only";
            }
            else if (!trailerValid)
            {
                std::cout << "INVALID acc bits!";
            }
            else
            {
                const char* desc = isTrailer ? trailAccShort[accIdx[b]] : dataAccShort[accIdx[b]];
                std::cout << GRAY << "[" << (int)accC1[b] << (int)accC2[b] << (int)accC3[b] << "] " << RESET << desc;
            }

            std::cout << "\n";
        }
        std::cout << "\n";
        return;
    }

    // Modalità dettaglio blocco specifico
    auto resp = m_mifare->readBlock(sector, relBlock);
    if (!resp.success)
    {
        std::cout << "[-] Read failed. " << PCSCReader::decodeSW(resp.sw1, resp.sw2) << "\n";
        return;
    }

    const auto& d        = resp.data;
    const int   absBlock = MifareClassic::toAbsBlock(sector, relBlock);

    auto printGroup = [&](int from, int to, const char* color) {
        for (int i = from; i <= to; ++i)
        {
            std::cout << color << hx(d[i]) << RESET;
            if (i < to) std::cout << " ";
        }
    };

    const bool isMfr     = (sector == 0 && relBlock == 0);
    const bool isTrailer = (relBlock == 3);

    bool isValue = false;
    if (!isMfr && !isTrailer && d.size() == 16)
    {
        isValue = true;
        for (int i = 0; i < 4 && isValue; ++i)
        {
            if (d[i] != d[i + 8])           isValue = false;
            if (d[i] != (uint8_t)~d[i + 4]) isValue = false;
        }
        if (d[12] != d[14])            isValue = false;
        if (d[12] != (uint8_t)~d[13]) isValue = false;
    }

    const char* typeLabel = isMfr     ? "Manufacturer Block  [read-only]" :
                            isTrailer ? "Sector Trailer" :
                            isValue   ? "Value Block" :
                                        "Data Block";

    std::cout << "[+] S" << sector << "/B" << relBlock
              << "  abs=" << absBlock << "  "
              << BOLD << "[" << typeLabel << "]" << RESET << "\n";

    std::cout << "    ";
    if (isMfr)
    {
        printGroup(0, 3, UID);        std::cout << "  ";
        printGroup(4, 15, MFR_DATA);
    }
    else if (isTrailer)
    {
        printGroup(0, 5, KEY_A);      std::cout << "  ";
        printGroup(6, 9, ACCESS_BITS); std::cout << "  ";
        printGroup(10, 15, KEY_B);
    }
    else if (isValue)
    {
        printGroup(0, 3, VALUE_BLOCK);  std::cout << "  ";
        printGroup(4, 7, GRAY);         std::cout << "  ";
        printGroup(8, 11, VALUE_BLOCK); std::cout << "  ";
        printGroup(12, 15, VALUE_BLOCK);
    }
    else
    {
        printGroup(0, 7, DATA_BLOCK);  std::cout << "  ";
        printGroup(8, 15, DATA_BLOCK);
    }
    std::cout << "\n";

    if (isMfr)
    {
        std::cout << "    " << UID << "NUID    " << RESET << ": " << UID;
        for (int i = 0; i < 4;  ++i) std::cout << hx(d[i]) << (i < 3  ? " " : "");
        std::cout << RESET << "\n";

        std::cout << "    " << MFR_DATA << "Mfr Data" << RESET << ": " << MFR_DATA;
        for (int i = 4; i < 16; ++i) std::cout << hx(d[i]) << (i < 15 ? " " : "");
        std::cout << RESET << "\n";
    }
    else if (isTrailer)
    {
        std::cout << "    " << KEY_A << "KeyA    " << RESET
                  << ": " << KEY_A << "(hidden by IC)\n" << RESET;

        const bool valid =
            ((d[6] & 0x0F) == ((~d[7] >> 4) & 0x0F)) &&
            ((d[6] >>  4)  == ((~d[8])       & 0x0F)) &&
            ((d[7] & 0x0F) == ((~d[8] >> 4)  & 0x0F));

        std::cout << "    " << ACCESS_BITS << "AccBits " << RESET << ": ";

        if (!valid)
        {
            std::cout << BOLD << "INVALID - sector may be locked!\n" << RESET;
        }
        else
        {
            std::cout << ACCESS_BITS << hx(d[6]) << " " << hx(d[7]) << " " << hx(d[8]) << RESET
                      << "  UserByte=" << GRAY << hx(d[9]) << RESET << "\n";

            static const char* dataAcc[8] = {
                "transport   r/w/inc/dec : KeyA|B",
                "value (nr)  r+dec       : KeyA|B  (non-rechargeable)",
                "read-only   r           : KeyA|B",
                "r/w KeyB    r/w         : KeyB",
                "r/w         r: KeyA|B   w: KeyB",
                "read KeyB   r           : KeyB",
                "value       r+dec: KeyA|B  w+inc: KeyB",
                "blocked     no access"
            };
            static const char* trailAcc[8] = {
                "KeyB readable : w-KeyA=A  acc-r=A  keyB=rw-A",
                "transport     : acc=rw-A  keyB=rw-A",
                "              : acc-r=A  keyB=r-A  (no writes)",
                "              : w-KeyA=B  acc=rw-B  keyB=w-B",
                "              : w-KeyA=B  acc-r=A|B  keyB=w-B",
                "              : acc=rw-B",
                "write-protect : acc-r=A|B",
                "locked        : acc-r=A|B"
            };

            for (int b = 0; b < 4; ++b)
            {
                const uint8_t c1  = (d[7] >> (4 + b)) & 1;
                const uint8_t c2  = (d[8] >>       b)  & 1;
                const uint8_t c3  = (d[8] >> (4 + b)) & 1;
                const uint8_t idx = (c1 << 2) | (c2 << 1) | c3;
                const char*  desc = (b == 3) ? trailAcc[idx] : dataAcc[idx];

                std::cout << "    " << ACCESS_BITS
                          << "B" << b << (b == 3 ? " (trailer)" : "          ")
                          << RESET << ": "
                          << "[" << (int)c1 << (int)c2 << (int)c3 << "]  "
                          << GRAY << desc << RESET << "\n";
            }
        }

        std::cout << "    " << KEY_B << "KeyB    " << RESET << ": " << KEY_B;
        for (int i = 10; i < 16; ++i) std::cout << hx(d[i]) << (i < 15 ? " " : "");
        std::cout << RESET << "\n";
    }
    else if (isValue)
    {
        const int32_t val = static_cast<int32_t>(
            d[0] | (d[1] << 8) | (d[2] << 16) | (d[3] << 24));

        std::ostringstream hexVal, hexAdr;
        hexVal << "0x" << std::uppercase << std::hex
               << std::setw(8) << std::setfill('0') << static_cast<uint32_t>(val);
        hexAdr << "0x" << std::uppercase << std::hex
               << std::setw(2) << std::setfill('0') << static_cast<int>(d[12]);

        std::cout << "    " << VALUE_BLOCK << "Value   " << RESET << ": "
                  << VALUE_BLOCK << std::dec << val << RESET
                  << "  " << GRAY << hexVal.str() << RESET << "\n";

        std::cout << "    " << VALUE_BLOCK << "Address " << RESET << ": "
                  << VALUE_BLOCK << std::dec << static_cast<int>(d[12]) << RESET
                  << "  " << GRAY << hexAdr.str() << RESET << "\n";
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

    std::string uidStr;

    auto resp = m_mifare->readBlock(0, 0);
    if (resp.success && resp.data.size() >= 4)
    {
        std::ostringstream ss;
        for (int i = 0; i < 4; ++i)
            ss << std::uppercase << std::hex
                << std::setw(2) << std::setfill('0') << (int)resp.data[i];
        uidStr = ss.str();
    }

    if (uidStr.empty())
    {
        std::ostringstream ss;
        ss << "UNKNOWN_" << std::dec << static_cast<long>(std::time(nullptr));
        uidStr = ss.str();
    }

    namespace fs = std::filesystem;
    try { fs::create_directories("dumps"); }
    catch (const std::exception& e)
    {
        std::cout << "[-] Cannot create dumps/ folder: " << e.what() << "\n";
        return;
    }

    const std::string filename = "dumps/dump_" + uidStr + ".mfd";

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
            const auto& bd = mem[s][b];

            // Inizializza a zero: blocchi non letti -> 16 byte 0x00
            std::vector<uint8_t> row(16, 0x00);
            if (bd.ok && bd.data.size() == 16)
                row = bd.data;

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
        return;
    }

    // Prefisso "dumps/" se non già presente
    std::string fullPath = filename;
    if (filename.find("dumps/") == std::string::npos)
        fullPath = "dumps/" + filename;

    // Verifica esistenza file
    std::ifstream file(fullPath, std::ios::binary);
    if (!file)
    {
        std::cout << "[-] File not found: " << fullPath << "\n";
        return;
    }

    // Leggi 1024 byte (64 blocchi × 16 byte)
    std::vector<uint8_t> data(1024);
    file.read(reinterpret_cast<char*>(data.data()), 1024);
    auto bytesRead = file.gcount();
    file.close();

    if (bytesRead != 1024)
    {
        std::cout << "[-] Corrupted file: expected 1024 bytes, got " << bytesRead << "\n";
        return;
    }

    // Helper per formattazione hex
    auto hx = [](uint8_t b) {
        std::ostringstream ss;
        ss << std::uppercase << std::hex << std::setw(2) << std::setfill('0') << (int)b;
        return ss.str();
        };

    // Estrai UID dal blocco 0
    std::string uidStr;
    for (int i = 0; i < 4; ++i)
        uidStr += hx(data[i]) + (i < 3 ? " " : "");

    // Decodifica per ogni settore
    for (int s = 0; s < MifareClassic::SECTORS; ++s)
    {
        const int baseOffset = s * MifareClassic::BLOCKS_PER_SECTOR * 16;

        // Leggi sector trailer per access bits
        const int trailerOffset = baseOffset + (3 * 16);
        uint8_t accC1[4] = {}, accC2[4] = {}, accC3[4] = {}, accIdx[4] = {};
        bool trailerValid = false;

        const auto& t6 = data[trailerOffset + 6];
        const auto& t7 = data[trailerOffset + 7];
        const auto& t8 = data[trailerOffset + 8];

        trailerValid =
            ((t6 & 0x0F) == ((~t7 >> 4) & 0x0F)) &&
            ((t6 >> 4) == ((~t8) & 0x0F)) &&
            ((t7 & 0x0F) == ((~t8 >> 4) & 0x0F));

        if (trailerValid)
        {
            for (int b = 0; b < 4; ++b)
            {
                accC1[b] = (t7 >> (4 + b)) & 1;
                accC2[b] = (t8 >> b) & 1;
                accC3[b] = (t8 >> (4 + b)) & 1;
                accIdx[b] = (accC1[b] << 2) | (accC2[b] << 1) | accC3[b];
            }
        }

        static const char* dataAccShort[8] = {
            "r/w/inc/dec  KeyA|B",
            "r+dec  KeyA|B  (value NR)",
            "r  KeyA|B",
            "r/w  KeyB",
            "r:KeyA|B  w:KeyB",
            "r  KeyB",
            "r+dec:A|B  inc:B  (value)",
            "blocked"
        };
        static const char* trailAccShort[8] = {
            "KeyB readable",
            "transport  acc:A  keyB:rw-A",
            "acc-r:A  keyB-r:A",
            "w-KeyA:B  acc:B  keyB:B",
            "w-KeyA:B  acc-r:A|B  keyB:B",
            "acc:B",
            "write-protect  acc-r:A|B",
            "locked  acc-r:A|B"
        };

        std::cout << BOLD << "[Sector " << s << "]" << RESET << "\n";
        std::cout << "  Blk  Abs | 00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F | ASCII            | [CxN] Access\n";
        std::cout << "  --------   ------------------------------------------------   ----------------   -------------\n";

        for (int b = 0; b < MifareClassic::BLOCKS_PER_SECTOR; ++b)
        {
            const int absBlock = s * 4 + b;
            const int blockOffset = baseOffset + (b * 16);

            std::cout << "  B" << b << " [" << hx(absBlock) << "]  | ";

            const bool isMfr = (s == 0 && b == 0);
            const bool isTrailer = (b == 3);

            // Verifica se è un value block
            bool isValue = false;
            if (!isMfr && !isTrailer)
            {
                isValue = true;
                for (int i = 0; i < 4 && isValue; ++i)
                {
                    if (data[blockOffset + i] != data[blockOffset + i + 8]) isValue = false;
                    if (data[blockOffset + i] != (uint8_t)~data[blockOffset + i + 4]) isValue = false;
                }
                if (data[blockOffset + 12] != data[blockOffset + 14]) isValue = false;
                if (data[blockOffset + 12] != (uint8_t)~data[blockOffset + 13]) isValue = false;
            }

            auto byteColor = [&](int i) -> const char* {
                if (isMfr)     return i < 4 ? UID : MFR_DATA;
                if (isTrailer) return i < 6 ? KEY_A : i < 10 ? ACCESS_BITS : KEY_B;
                if (isValue)   return i < 4 ? VALUE_BLOCK : i < 8 ? GRAY : i < 12 ? VALUE_BLOCK : VALUE_BLOCK;
                return DATA_BLOCK;
                };

            // Hex colorato
            for (int i = 0; i < 16; ++i)
            {
                if (i == 8) std::cout << " ";
                std::cout << byteColor(i) << hx(data[blockOffset + i]) << RESET << " ";
            }

            // ASCII
            std::cout << "| ";
            for (int i = 0; i < 16; ++i)
            {
                uint8_t byte = data[blockOffset + i];
                std::cout << (std::isprint(byte) ? (char)byte : '.');
            }

            // Colonna Access
            std::cout << " | ";
            if (isMfr)
            {
                std::cout << "[mfr] read-only";
            }
            else if (!trailerValid)
            {
                std::cout << "INVALID acc bits!";
            }
            else
            {
                const char* desc = isTrailer ? trailAccShort[accIdx[b]] : dataAccShort[accIdx[b]];
                std::cout << GRAY << "[" << (int)accC1[b] << (int)accC2[b] << (int)accC3[b] << "] " << RESET << desc;
            }

            std::cout << "\n";
        }
        std::cout << "\n";
    }
}

void CommandParser::run()
{
    using namespace Color;

    if (!initializeReader())
        return;

    std::string selectedReader = m_reader->listReaders()[0];
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
            if (m_reader->waitAndConnect(selectedReader, 5))
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
                cmd == "dump" || cmd == "authenticate")
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
        else if (cmd == "read") { cmdRead(iss); }
        else if (cmd == "dump") { cmdDumpFile(); }
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
