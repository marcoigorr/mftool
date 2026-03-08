#include "command_parser.h"
#include "../core/pcsc_reader.h"
#include "../mifare/mifare_classic.h"
#include "../utils/logger.h"
#include "../utils/atr_parser.h"
#include "../utils/hex.h"
#include <iostream>
#include <sstream>
#include <fstream>
#include <filesystem>
#include <iomanip>
#include <cctype>
#include <ctime>

// ============================================================================
// SCHEMA COLORI GLOBALE - Solo per dati MIFARE
// ============================================================================
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

// ---------------------------------------------------------------------------
// decodeSW
// ---------------------------------------------------------------------------
std::string CommandParser::decodeSW(uint8_t sw1, uint8_t sw2)
{
    if (sw1 == 0x90 && sw2 == 0x00) return "Success";
    if (sw1 == 0x61)                return "More bytes available (SW2 = count)";

    // --- MIFARE / ACR122U ---
    if (sw1 == 0x63 && sw2 == 0x00) return "Authentication failed (wrong key)";
    if (sw1 == 0x65 && sw2 == 0x81) return "Memory failure (write error)";
    if (sw1 == 0x69 && sw2 == 0x82) return "Security status not satisfied (sector not authenticated)";
    if (sw1 == 0x69 && sw2 == 0x86) return "Command not allowed";
    if (sw1 == 0x6F && sw2 == 0x01) return "Card removed / communication error";
    if (sw1 == 0x6F && sw2 == 0x04) return "Authentication failed / no suitable key found";
    if (sw1 == 0x6F && sw2 == 0x12) return "Auth OK but block not readable (access conditions)";

    // --- Standard ISO 7816 ---
    if (sw1 == 0x67 && sw2 == 0x00) return "Wrong length (Lc/Le incorrect)";
    if (sw1 == 0x6A && sw2 == 0x81) return "Function not supported";
    if (sw1 == 0x6A && sw2 == 0x82) return "File/block not found";
    if (sw1 == 0x6A && sw2 == 0x86) return "Incorrect P1/P2";
    if (sw1 == 0x6D && sw2 == 0x00) return "INS not supported";
    if (sw1 == 0x6E && sw2 == 0x00) return "CLA not supported";
    if (sw1 == 0x6F && sw2 == 0x00) return "Unknown error";

    std::stringstream ss;
    ss << "SW " << std::uppercase << std::hex
       << std::setw(2) << std::setfill('0') << (int)sw1
       << std::setw(2) << std::setfill('0') << (int)sw2;
    return ss.str();
}

// ---------------------------------------------------------------------------
// showHelp
// ---------------------------------------------------------------------------
void CommandParser::showHelp() const
{
    using namespace Color;
    std::cout << "\n" << BOLD << "================ MFTOOL COMMANDS ================" << RESET << "\n";
    std::cout << "  tagid\n";
    std::cout << "      Legge NUID + Manufacturer Data dal blocco 0 (S0/B0)\n";
    std::cout << "      Autentica automaticamente con Key A (default A0A1A2A3A4A5)\n\n";
    std::cout << "  scan [-k <keyfile>]\n";
    std::cout << "      Prova tutti i 16 settori con tutte le chiavi (KeyA + KeyB)\n";
    std::cout << "      Default keyfile: keys/found.keys\n\n";
    std::cout << "  authenticate -s <settore> [-k <keyfile>] [-t A|B] [-key <12 hex>]\n";
    std::cout << "      Autentica un settore. Senza -t prova prima KeyA poi KeyB.\n\n";
    std::cout << "  read -s <settore> [-b <blocco>]\n";
    std::cout << "      Senza -b: tabella hex + ASCII + Access di tutti i 4 blocchi\n";
    std::cout << "      Con -b:  decodifica dettagliata del singolo blocco (blocco 0-3)\n\n";
    std::cout << "  write -s <settore> -b <blocco> -d <32 hex chars>\n";
    std::cout << "      Scrive 16 byte su un blocco autenticato\n";
    std::cout << "      Es: write -s 1 -b 0 -d 48656C6C6F000000000000000000000\n\n";
    std::cout << "  dump\n";
    std::cout << "      Legge tutti i 64 blocchi (16 settori) e salva in dumps/<UID>.mfd\n";
    std::cout << "      Formato: MIFARE Dump binario (1024 byte, standard universale)\n";
    std::cout << "      Richiede scan preventivo per autenticazione\n\n";
    std::cout << "  readdump <filename>\n";
    std::cout << "      Legge e visualizza un file dump .mfd dalla cartella dumps/\n";
    std::cout << "      Mostra contenuto con decodifica Access Bits e Value Blocks\n";
    std::cout << "      Es: readdump dump_3A165647.mfd\n\n";
    std::cout << "  help    Mostra questo messaggio\n";
    std::cout << "  exit    Esci dal programma\n";
    std::cout << BOLD << "=================================================" << RESET << "\n\n";
}

// ---------------------------------------------------------------------------
// initializeReader
// ---------------------------------------------------------------------------
bool CommandParser::initializeReader()
{
    try
    {
        m_reader = std::make_unique<PCSCReader>();
        m_reader->establishContext();

        auto readers = m_reader->listReaders();
        if (readers.empty())
        {
            Logger::error("No readers found");
            return false;
        }

        Logger::info("Found " + std::to_string(readers.size()) + " reader(s)");
        Logger::info("Using reader: " + readers[0]);
        return true;
    }
    catch (const std::exception& e)
    {
        Logger::error(std::string("Initialization failed: ") + e.what());
        return false;
    }
}

// ---------------------------------------------------------------------------
// autoAuth
// ---------------------------------------------------------------------------
bool CommandParser::autoAuth(int sector, const std::string& keyFile)
{
    if (m_mifare->isAuthenticated(sector))
        return true;

    auto keys = MifareClassic::loadKeys(keyFile);
    for (const auto& key : keys)
    {
        if (m_mifare->authenticate(sector, key, 'A')) return true;
        if (m_mifare->authenticate(sector, key, 'B')) return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// cmdTagID
// ---------------------------------------------------------------------------
void CommandParser::cmdTagID()
{
    using namespace Color;
    
    const std::vector<uint8_t> defaultKey = { 0xA0,0xA1,0xA2,0xA3,0xA4,0xA5 };
    const std::string          keyFile    = "keys/found.keys";

    bool authed = m_mifare->authenticate(0, defaultKey, 'A');

    if (!authed)
    {
        auto keys = MifareClassic::loadKeys(keyFile);
        for (const auto& key : keys)
        {
            if (m_mifare->authenticate(0, key, 'A')) { authed = true; break; }
            if (m_mifare->authenticate(0, key, 'B')) { authed = true; break; }
        }
    }

    if (!authed)
    {
        std::cout << "[-] Autenticazione settore 0 fallita.\n"
                  << "    Usare prima: authenticate -s 0 [-k <keyfile>]\n";
        return;
    }

    auto resp = m_mifare->readBlock(0, 0);
    if (!resp.success)
    {
        std::cout << "[-] Lettura Manufacturer Block fallita. "
                  << decodeSW(resp.sw1, resp.sw2) << "\n";
        return;
    }

    const auto& d = resp.data;

    auto hx = [](uint8_t b) {
        std::ostringstream ss;
        ss << std::uppercase << std::hex << std::setw(2) << std::setfill('0') << (int)b;
        return ss.str();
    };

    std::cout << "[+] Manufacturer Block (S0/B0 - read only)\n";

    std::cout << "    ";
    for (int i = 0; i < 16; ++i)
    {
        if (i == 0) std::cout << UID;
        if (i == 4) std::cout << RESET << " " << MFR_DATA;
        std::cout << hx(d[i]);
        if (i < 15) std::cout << " ";
    }
    std::cout << RESET << "\n";

    std::cout << "    " << UID << "NUID    " << RESET << ": " << UID;
    for (int i = 0; i < 4;  ++i) std::cout << hx(d[i]) << (i < 3  ? " " : "");
    std::cout << RESET << "\n";

    std::cout << "    " << MFR_DATA << "Mfr Data" << RESET << ": " << MFR_DATA;
    for (int i = 4; i < 16; ++i) std::cout << hx(d[i]) << (i < 15 ? " " : "");
    std::cout << RESET << "\n";
}

// ---------------------------------------------------------------------------
// cmdAuthenticate
// ---------------------------------------------------------------------------
void CommandParser::cmdAuthenticate(std::istringstream& args)
{
    using namespace Color;
    
    int         sector  = -1;
    std::string keyFile = "keys/found.keys";
    char        keyType = '\0';
    std::string inlineKey;

    std::string token;
    while (args >> token)
    {
        if      (token == "-s"   && args >> token) sector    = std::stoi(token);
        else if (token == "-k"   && args >> token) keyFile   = token;
        else if (token == "-t"   && args >> token) keyType   = (char)std::toupper(token[0]);
        else if (token == "-key" && args >> token) inlineKey = token;
    }

    if (sector < 0 || sector > 15)
    {
        std::cout << "[!] Uso: authenticate -s <settore 0-15> [-k <keyfile>] [-t A|B] [-key <12 hex>]\n";
        return;
    }

    std::vector<std::vector<uint8_t>> keys;

    if (!inlineKey.empty())
    {
        try   { keys.push_back(Hex::stringToBytes(inlineKey)); }
        catch (const std::invalid_argument& e)
        {
            std::cout << "[!] Chiave hex non valida: " << e.what() << "\n";
            return;
        }
        if (keys[0].size() != 6)
        {
            std::cout << "[!] La chiave deve essere 6 byte (12 hex chars).\n";
            return;
        }
    }
    else
    {
        keys = MifareClassic::loadKeys(keyFile);
        if (keys.empty())
        {
            std::cout << "[!] Nessuna chiave valida in: " << keyFile << "\n";
            return;
        }
    }

    bool ok = false;

    if (keyType == '\0')
    {
        ok = m_mifare->tryAuthenticate(sector, keys);
    }
    else
    {
        for (const auto& key : keys)
        {
            if (m_mifare->authenticate(sector, key, keyType))
            {
                ok = true;
                break;
            }
        }
    }

    if (ok)
    {
        const auto& auth = m_mifare->getSectorAuth(sector);
        const char* keyColor = (auth.keyType == 'A') ? KEY_A : KEY_B;
        
        std::cout << "[+] Settore " << sector
                  << " autenticato (" << keyColor << "Key" << auth.keyType << RESET << "): "
                  << keyColor << Hex::bytesToString(auth.key) << RESET << "\n";
    }
    else
    {
        std::cout << "[-] Autenticazione fallita per il settore " << sector
                  << " con " << keys.size() << " chiave/i.\n";
    }
}

// ---------------------------------------------------------------------------
// cmdScan
// ---------------------------------------------------------------------------
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
        std::cout << "[!] Nessuna chiave valida in: " << keyFile << "\n";
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
              << " settori con " << keys.size() << " chiave/i (KeyA + KeyB)...\n\n";

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

        // Ripristina KeyA come auth principale
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
    std::cout << "\n[+] Risultati: "
              << KEY_A << crackedA << "/16" << RESET << " KeyA,  "
              << KEY_B << crackedB << "/16" << RESET << " KeyB trovate.\n\n";
}

// ---------------------------------------------------------------------------
// cmdRead
// ---------------------------------------------------------------------------
void CommandParser::cmdRead(std::istringstream& args)
{
    using namespace Color;
    
    int sector   = -1;
    int relBlock = -1;

    std::string token;
    while (args >> token)
    {
        if      (token == "-s" && args >> token) sector   = std::stoi(token);
        else if (token == "-b" && args >> token) relBlock = std::stoi(token);
    }

    if (sector < 0 || sector > 15 || (relBlock != -1 && (relBlock < 0 || relBlock > 3)))
    {
        std::cout << "[!] Uso: read -s <settore 0-15> [-b <blocco 0-3>]\n";
        return;
    }

    if (!autoAuth(sector))
    {
        std::cout << "[-] Autenticazione settore " << sector << " fallita.\n"
                  << "    Esegui prima: authenticate -s " << sector << " [-k <keyfile>]\n";
        return;
    }

    auto hx = [](uint8_t b) {
        std::ostringstream ss;
        ss << std::uppercase << std::hex << std::setw(2) << std::setfill('0') << (int)b;
        return ss.str();
    };

    // =========================================================================
    // MODALITÀ TABELLA: read -s <sector>
    // =========================================================================
    if (relBlock == -1)
    {
        std::vector<APDUResponse> resps(MifareClassic::BLOCKS_PER_SECTOR);
        for (int b = 0; b < MifareClassic::BLOCKS_PER_SECTOR; ++b)
            resps[b] = m_mifare->readBlock(sector, b);

        // Decode access bits da sector trailer (B3)
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
                std::cout << "lettura fallita: " << decodeSW(resp.sw1, resp.sw2) << "\n";
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

    // =========================================================================
    // MODALITÀ SINGOLO BLOCCO: read -s <sector> -b <block>
    // =========================================================================
    auto resp = m_mifare->readBlock(sector, relBlock);
    if (!resp.success)
    {
        std::cout << "[-] Lettura fallita. " << decodeSW(resp.sw1, resp.sw2) << "\n";
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
            std::cout << BOLD << "INVALID - settore potenzialmente bloccato!\n" << RESET;
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

// ---------------------------------------------------------------------------
// cmdDumpFile
// ---------------------------------------------------------------------------
void CommandParser::cmdDumpFile()
{
    for (int s = 0; s < MifareClassic::SECTORS; ++s)
    {
        if (!m_mifare->isAuthenticated(s))
        {
            Logger::error("Non autenticato al settore " + std::to_string(s) + ". Eseguire prima uno scan.");
            return;
        }
    }

    using namespace Color;
    
    // -------------------------------------------------------------------------
    // NUID dal Manufacturer Block (S0/B0) -> nome file
    // -------------------------------------------------------------------------
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
        std::cout << "[-] Impossibile creare la cartella dumps/: " << e.what() << "\n";
        return;
    }

    const std::string filename = "dumps/dump_" + uidStr + ".mfd";

    // -------------------------------------------------------------------------
    // Lettura di tutti i 64 blocchi
    // -------------------------------------------------------------------------
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

    std::cout << "\n" << BOLD << "Dump " << MifareClassic::SECTORS
              << " settori -> " << filename << RESET << "\n\n";

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

    // -------------------------------------------------------------------------
    // Scrittura file .mfd (formato binario standard)
    // -------------------------------------------------------------------------
    std::ofstream out(filename, std::ios::binary);
    if (!out)
    {
        std::cout << "[-] Impossibile aprire " << filename << " in scrittura\n";
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
            // L'IC maschera Key A nella risposta READ BINARY (hardware by design)
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

    std::cout << "\n[+] Salvato: " << filename << "\n";
    std::cout << "    Formato: MIFARE Dump (.mfd) - 1024 byte binari\n";
    std::cout << "    Blocchi letti: " << nOk << "/64"
              << "  Non letti: " << nFail << "\n\n";
}

// ---------------------------------------------------------------------------
// cmdReadDump
// Legge e visualizza un file dump .mfd
// ---------------------------------------------------------------------------
void CommandParser::cmdReadDump(std::istringstream& args)
{
    using namespace Color;

    std::string filename;
    if (!(args >> filename))
    {
        std::cout << "[!] Uso: readdump <filename>\n";
        std::cout << "    Es: readdump dump_3A165647.mfd\n";
        return;
    }

    // Prepend "dumps/" se non già presente
    std::string fullPath = filename;
    if (filename.find("dumps/") == std::string::npos)
        fullPath = "dumps/" + filename;

    // Verifica esistenza file
    std::ifstream file(fullPath, std::ios::binary);
    if (!file)
    {
        std::cout << "[-] File non trovato: " << fullPath << "\n";
        return;
    }

    // Leggi 1024 byte (64 blocchi × 16 byte)
    std::vector<uint8_t> data(1024);
    file.read(reinterpret_cast<char*>(data.data()), 1024);
    auto bytesRead = file.gcount();
    file.close();

    if (bytesRead != 1024)
    {
        std::cout << "[-] File corrotto: attesi 1024 byte, letti " << bytesRead << "\n";
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

    std::cout << "\n" << BOLD << "=== DUMP FILE: " << filename << " ===" << RESET << "\n";
    std::cout << "UID: " << UID << uidStr << RESET << "\n\n";

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

// ---------------------------------------------------------------------------
// cmdWrite
// ---------------------------------------------------------------------------
void CommandParser::cmdWrite(std::istringstream& args)
{
    using namespace Color;
    
    int         sector   = -1;
    int         relBlock = -1;
    std::string hexData;

    std::string token;
    while (args >> token)
    {
        if      (token == "-s" && args >> token) sector   = std::stoi(token);
        else if (token == "-b" && args >> token) relBlock = std::stoi(token);
        else if (token == "-d" && args >> token) hexData  = token;
    }

    if (sector < 0 || sector > 15 || relBlock < 0 || relBlock > 3 || hexData.empty())
    {
        std::cout << "[!] Uso: write -s <settore 0-15> -b <blocco 0-3> -d <32 hex chars>\n";
        return;
    }

    if (!autoAuth(sector))
    {
        std::cout << "[-] Autenticazione settore " << sector << " fallita.\n"
                  << "    Esegui prima: authenticate -s " << sector << " [-k <keyfile>]\n";
        return;
    }

    if (relBlock == 3)
    {
        std::cout << "[!] ATTENZIONE: stai scrivendo sul sector trailer (blocco 3).\n"
                  << "    Contiene " << KEY_A << "KeyA" << RESET << " + "
                  << ACCESS_BITS << "Access Bits" << RESET << " + "
                  << KEY_B << "KeyB" << RESET << ". Una scrittura errata\n"
                  << "    puo' rendere il settore " << sector << " inaccessibile.\n"
                  << "    Continua? [s/N] ";
        std::string confirm;
        std::getline(std::cin, confirm);
        if (confirm != "s" && confirm != "S") { std::cout << "Annullato.\n"; return; }
    }

    std::vector<uint8_t> data;
    try   { data = Hex::stringToBytes(hexData); }
    catch (const std::invalid_argument& e)
    {
        std::cout << "[!] Dati hex non validi: " << e.what() << "\n";
        return;
    }

    if (data.size() != 16)
    {
        std::cout << "[!] Devono essere esattamente 16 byte (32 hex chars). "
                  << "Ricevuti: " << data.size() << " byte.\n";
        return;
    }

    auto resp = m_mifare->writeBlock(sector, relBlock, data);
    if (!resp.success)
    {
        std::cout << "[-] Scrittura fallita. " << decodeSW(resp.sw1, resp.sw2) << "\n";
        if (!resp.errorMessage.empty()) std::cout << "    " << resp.errorMessage << "\n";
        return;
    }

    int absBlock = MifareClassic::toAbsBlock(sector, relBlock);
    std::cout << "[+] S" << sector << "/B" << relBlock
              << " (assoluto " << absBlock << ") scritto.\n";
    std::cout << "    HEX: " << Hex::bytesToString(data) << "\n";
}

// ---------------------------------------------------------------------------
// run
// ---------------------------------------------------------------------------
void CommandParser::run()
{
    using namespace Color;
    
    if (!initializeReader())
        return;

    std::string selectedReader = m_reader->listReaders()[0];
    bool shouldExit = false;

    while (!shouldExit)
    {
        Logger::info("Waiting for a tag... (press Ctrl+C to exit)");

        if (!m_reader->waitAndConnect(selectedReader))
            continue;

        // Nuovo tag: crea una nuova istanza di MifareClassic (auth state azzerato)
        m_mifare = std::make_unique<MifareClassic>(*m_reader);

        // Mostra informazioni sul tag
        CardInfo info = m_reader->getCardInfo();
        Logger::info("ATR:  " + Hex::bytesToString(info.atr));
        Logger::info("TYPE: " + ATRParser::getCardType(info.atr) + "\n");
        std::cout << "Type 'help' for commands, 'exit' to quit.\n\n";

        // Shell interattiva: attiva finché il tag è presente
        while (!shouldExit && m_reader->getCardInfo().cardState == "Present")
        {
            std::cout << "> ";
            std::string line;
            std::getline(std::cin, line);

            if (m_reader->getCardInfo().cardState != "Present")
                break;

            std::istringstream iss(line);
            std::string cmd;
            iss >> cmd;

            if      (cmd == "exit")         { shouldExit = true; }
            else if (cmd == "help")         { showHelp(); }
            else if (cmd == "tagid")        { cmdTagID(); }
            else if (cmd == "scan")         { cmdScan(iss); }
            else if (cmd == "authenticate") { cmdAuthenticate(iss); }
            else if (cmd == "read")         { cmdRead(iss); }
            else if (cmd == "write")        { cmdWrite(iss); }
            else if (cmd == "dump")         { cmdDumpFile(); }
            else if (cmd == "readdump")     { cmdReadDump(iss); }
            else if (!cmd.empty())
                std::cout << "[!] Comando sconosciuto. Digita 'help'.\n";
        }

        if (!shouldExit)
        {
            Logger::error("Tag removed");
            m_reader->disconnect();
        }
    }

    m_reader->disconnect();
    m_reader->releaseContext();
}

// ---------------------------------------------------------------------------
// run
// ---------------------------------------------------------------------------
void CommandParser::run2()
{
    using namespace Color;

    if (!initializeReader())
        return;

    std::string selectedReader = m_reader->listReaders()[0];
    bool shouldExit = false;
    bool tagPresent = false;

    std::cout << "\n" << BOLD << "========== MFTOOL Interactive Shell ==========" << RESET << "\n";
    std::cout << "Type 'help' for commands, 'exit' to quit.\n";
    std::cout << "Offline commands: help, readdump, exit\n";
    std::cout << "Tag required: scan, read, write, dump, tagid, authenticate\n\n";

    // Shell interattiva sempre attiva
    while (!shouldExit)
    {
        // Prompt diverso in base alla presenza del tag
        if (tagPresent)
            std::cout << BOLD << "[TAG]" << RESET << " > ";
        else
            std::cout << "> ";

        std::string line;
        std::getline(std::cin, line);

        std::istringstream iss(line);
        std::string cmd;
        iss >> cmd;

        // =====================================================================
        // COMANDI OFFLINE - funzionano sempre
        // =====================================================================
        if (cmd == "exit")
        {
            shouldExit = true;
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

        // =====================================================================
        // COMANDO SPECIALE: connect
        // =====================================================================
        else if (cmd == "connect")
        {
            std::cout << "Waiting for tag...\n";
            if (m_reader->waitAndConnect(selectedReader, 5))  // 5 sec timeout
            {
                m_mifare = std::make_unique<MifareClassic>(*m_reader);
                CardInfo info = m_reader->getCardInfo();

                std::cout << "\n[+] TAG DETECTED\n";
                std::cout << "    ATR:  " << Hex::bytesToString(info.atr) << "\n";
                std::cout << "    TYPE: " << ATRParser::getCardType(info.atr) << "\n\n";

                tagPresent = true;
            }
            else
            {
                std::cout << "[-] No tag detected (timeout)\n";
                tagPresent = false;
            }
            continue;
        }

        // =====================================================================
        // COMANDI CHE RICHIEDONO TAG
        // =====================================================================

        // Verifica presenza tag prima di eseguire comandi che lo richiedono
        if (!tagPresent || !m_mifare)
        {
            if (cmd == "scan" || cmd == "read" || cmd == "write" ||
                cmd == "dump" || cmd == "tagid" || cmd == "authenticate")
            {
                std::cout << "[!] Nessun tag presente. Usa 'connect' per rilevare un tag.\n";
                continue;
            }

            if (!cmd.empty())
            {
                std::cout << "[!] Comando sconosciuto. Digita 'help'.\n";
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
            tagPresent = false;
            continue;
        }

        // Esegui comandi che richiedono il tag
        if (cmd == "tagid") { cmdTagID(); }
        else if (cmd == "scan") { cmdScan(iss); }
        else if (cmd == "authenticate") { cmdAuthenticate(iss); }
        else if (cmd == "read") { cmdRead(iss); }
        else if (cmd == "write") { cmdWrite(iss); }
        else if (cmd == "dump") { cmdDumpFile(); }
        else if (!cmd.empty())
        {
            std::cout << "[!] Comando sconosciuto. Digita 'help'.\n";
        }
    }

    if (tagPresent)
    {
        m_reader->disconnect();
    }
    m_reader->releaseContext();
    std::cout << "\n[+] Goodbye!\n";
}
