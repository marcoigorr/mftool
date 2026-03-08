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

CommandParser::CommandParser()  = default;
CommandParser::~CommandParser() = default;

// ---------------------------------------------------------------------------
// decodeSW
//
// Traduce SW1/SW2 in un messaggio leggibile.
// Copre i codici standard ISO 7816 e quelli specifici MIFARE / ACR122U.
// Riferimento: ACR122U API v2.04 + ISO/IEC 7816-4
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
    std::cout << "\n================ MFTOOL COMMANDS ================\n";
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
    std::cout << "  dump [-k <keyfile>] [-f mct|bin]\n";
    std::cout << "      Legge tutti i 64 blocchi (16 settori) e salva in dumps/<UID>.<fmt>\n";
    std::cout << "      -f mct  formato MIFARE Classic Tool (default, testo hex)\n";
    std::cout << "      -f bin  dump binario grezzo (1024 byte, blocchi mancanti = 0x00)\n";
    std::cout << "      Default keyfile: keys/found.keys\n\n";
    std::cout << "  help    Mostra questo messaggio\n";
    std::cout << "  exit    Esci dal programma\n";
    std::cout << "=================================================\n\n";
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
//
// Tenta l'autenticazione del settore tramite:
//   1. Stato già memorizzato (isAuthenticated)
//   2. Fallback: chiavi nel keyFile specificato (KeyA poi KeyB per ognuna)
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
//
// Legge il Manufacturer Block (Settore 0, Blocco 0 = blocco assoluto 0).
// Contenuto secondo NXP MF1S50yyX/V1 datasheet §8.6.1:
//   byte 0-3  : NUID (4 byte) oppure byte 0-6 per UID (7 byte)
//   byte 4-15 : Manufacturer Data (read-only, write-protected)
//
// Richiede autenticazione Key A sul settore 0.
// Prova prima la chiave di default (A0 A1 A2 A3 A4 A5 / transport config),
// poi le chiavi nel file keys/found.keys come fallback.
// ---------------------------------------------------------------------------
void CommandParser::cmdTagID()
{
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

    constexpr const char* CYAN   = "\033[96m";
    constexpr const char* YELLOW = "\033[93m";
    constexpr const char* RESET  = "\033[0m";

    auto hx = [](uint8_t b) {
        std::ostringstream ss;
        ss << std::uppercase << std::hex << std::setw(2) << std::setfill('0') << (int)b;
        return ss.str();
    };

    std::cout << "[+] Manufacturer Block (S0/B0 - read only)\n";

    std::cout << "    ";
    for (int i = 0; i < 16; ++i)
    {
        if (i == 0) std::cout << CYAN;
        if (i == 4) std::cout << RESET << " " << YELLOW;
        std::cout << hx(d[i]);
        if (i < 15) std::cout << " ";
    }
    std::cout << RESET << "\n";

    std::cout << "    " << CYAN   << "NUID    " << RESET << ": " << CYAN;
    for (int i = 0; i < 4;  ++i) std::cout << hx(d[i]) << (i < 3  ? " " : "");
    std::cout << RESET << "\n";

    std::cout << "    " << YELLOW << "Mfr Data" << RESET << ": " << YELLOW;
    for (int i = 4; i < 16; ++i) std::cout << hx(d[i]) << (i < 15 ? " " : "");
    std::cout << RESET << "\n";
}

// ---------------------------------------------------------------------------
// cmdAuthenticate
//
// Sintassi: authenticate -s <sector> [-k <keyfile>] [-t A|B] [-key <12 hex>]
//
// Senza -t: prova prima KeyA poi KeyB (tryAuthenticate).
// Con -t A o -t B: prova solo il tipo specificato con tutte le chiavi.
// Con -key: usa la chiave inline (12 hex chars) senza keyfile.
// Default keyfile: keys/found.keys
// ---------------------------------------------------------------------------
void CommandParser::cmdAuthenticate(std::istringstream& args)
{
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
        std::cout << "[+] Settore " << sector
                  << " autenticato (Key" << auth.keyType << "): "
                  << Hex::bytesToString(auth.key) << "\n";
    }
    else
    {
        std::cout << "[-] Autenticazione fallita per il settore " << sector
                  << " con " << keys.size() << " chiave/i.\n";
    }
}

// ---------------------------------------------------------------------------
// cmdScan
//
// Sintassi: scan [-k <keyfile>]
//
// Prova tutti i 16 settori con tutte le chiavi del file.
// Per ogni settore: prima tutte le chiavi con KeyA, poi con KeyB.
// Mostra una tabella con le chiavi trovate.
// Default keyfile: keys/found.keys
// ---------------------------------------------------------------------------
void CommandParser::cmdScan(std::istringstream& args)
{
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

    constexpr const char* GREEN = "\033[92m";
    constexpr const char* GRAY  = "\033[90m";
    constexpr const char* BOLD  = "\033[1m";
    constexpr const char* CYAN  = "\033[96m";
    constexpr const char* RESET = "\033[0m";

    // "A0 A1 A2 A3 A4 A5" = 17 chars
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

        // Ripristina KeyA come auth principale (usata da read)
        if (!keyAStr.empty())
            m_mifare->authenticate(s, m_mifare->getSectorAuth(s).keyA, 'A');

        const bool hasA = !keyAStr.empty();
        const bool hasB = !keyBStr.empty();

        std::cout << "  " << CYAN << "S" << secStr(s) << RESET << " | ";
        std::cout << (hasA ? GREEN : GRAY) << pad(hasA ? keyAStr : "----", KEY_W) << RESET;
        std::cout << " | ";
        std::cout << (hasB ? GREEN : GRAY) << (hasB ? keyBStr : "----") << RESET;
        std::cout << "\n";
    }

    std::cout << BOLD << hRule << "\n" << RESET;
    std::cout << "\n[+] Risultati: "
              << GREEN << crackedA << "/16" << RESET << " KeyA,  "
              << GREEN << crackedB << "/16" << RESET << " KeyB trovate.\n\n";
}

// ---------------------------------------------------------------------------
// cmdRead
//
// Sintassi: read -s <sector> [-b <block>]
//
// Senza -b  → tabella di tutti i 4 blocchi con colori per campo e
//             colonna Access [C1C2C3] sulla destra di ogni riga.
// Con    -b → decodifica dettagliata del singolo blocco con colori per tipo.
// ---------------------------------------------------------------------------
void CommandParser::cmdRead(std::istringstream& args)
{
    int sector   = -1;
    int relBlock = -1;   // -1 = non specificato → dump tabellare

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

    // Helper comune: formatta un byte come "A0" senza toccare lo stato di cout
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
        constexpr const char* RED     = "\033[91m";
        constexpr const char* GREEN   = "\033[92m";
        constexpr const char* YELLOW  = "\033[93m";
        constexpr const char* CYAN    = "\033[96m";
        constexpr const char* MAGENTA = "\033[95m";
        constexpr const char* GRAY    = "\033[90m";
        constexpr const char* BOLD    = "\033[1m";
        constexpr const char* RESET   = "\033[0m";

        // Leggi tutti e 4 i blocchi prima di stampare:
        // il sector trailer (B3) serve per decodificare gli access bit di tutti i blocchi.
        std::vector<APDUResponse> resps(MifareClassic::BLOCKS_PER_SECTOR);
        for (int b = 0; b < MifareClassic::BLOCKS_PER_SECTOR; ++b)
            resps[b] = m_mifare->readBlock(sector, b);

        // --- Decode access bits da sector trailer (B3) ---
        // NXP MF1S50yyX/V1 Figure 10:
        //   C1_b = bit (4+b) di byte 7
        //   C2_b = bit  b    di byte 8
        //   C3_b = bit (4+b) di byte 8
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

        // Descrizioni brevi per colonna Access (data block — NXP Table 8)
        static const char* dataAccShort[8] = {
            /*000*/ "r/w/inc/dec  KeyA|B",
            /*001*/ "r+dec  KeyA|B  (value NR)",
            /*010*/ "r  KeyA|B",
            /*011*/ "r/w  KeyB",
            /*100*/ "r:KeyA|B  w:KeyB",
            /*101*/ "r  KeyB",
            /*110*/ "r+dec:A|B  inc:B  (value)",
            /*111*/ "blocked"
        };
        // Descrizioni brevi per colonna Access (sector trailer — NXP Table 7)
        static const char* trailAccShort[8] = {
            /*000*/ "KeyB readable",
            /*001*/ "transport  acc:A  keyB:rw-A",
            /*010*/ "acc-r:A  keyB-r:A",
            /*011*/ "w-KeyA:B  acc:B  keyB:B",
            /*100*/ "w-KeyA:B  acc-r:A|B  keyB:B",
            /*101*/ "acc:B",
            /*110*/ "write-protect  acc-r:A|B",
            /*111*/ "locked  acc-r:A|B"
        };

        const auto& auth = m_mifare->getSectorAuth(sector);
        std::cout << "\n" << BOLD << "[Sector " << sector << "]" << RESET
                  << " Key" << auth.keyType << ": " << Hex::bytesToString(auth.key) << "\n";
        std::cout << "  Blk  Abs  | 00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F | ASCII            | [CxN] Access\n";
        std::cout << "  ---------   -----------------------------------------------   ----------------   -------------\n";

        for (int b = 0; b < MifareClassic::BLOCKS_PER_SECTOR; ++b)
        {
            const int   absBlock = MifareClassic::toAbsBlock(sector, b);
            const auto& resp     = resps[b];

            std::cout << "  B" << b << " [" << hx(static_cast<uint8_t>(absBlock)) << "]  | ";

            if (!resp.success)
            {
                std::cout << "-- lettura fallita: " << decodeSW(resp.sw1, resp.sw2) << "\n";
                continue;
            }

            const auto& d = resp.data;

            // Classificazione blocco
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

            // Colore per indice byte in base al tipo di blocco
            auto byteColor = [&](int i) -> const char* {
                if (isMfr)     return i <  4 ? CYAN   : YELLOW;
                if (isTrailer) return i <  6 ? RED    : i < 10 ? YELLOW : CYAN;
                if (isValue)   return i <  4 ? CYAN   : i <  8 ? GRAY   : i < 12 ? CYAN : YELLOW;
                return GREEN;
            };

            // Hex colorato per campo
            for (int i = 0; i < 16; ++i)
            {
                if (i == 8) std::cout << " ";
                std::cout << byteColor(i) << hx(d[i]) << RESET << " ";
            }

            // ASCII
            std::cout << "| ";
            for (uint8_t byte : d)
                std::cout << (std::isprint(byte) ? (char)byte : '.');

            // Colonna Access
            std::cout << " | ";
            if (isMfr)
            {
                std::cout << MAGENTA << "[mfr] read-only" << RESET;
            }
            else if (!trailerValid)
            {
                std::cout << RED << "INVALID acc bits!" << RESET;
            }
            else
            {
                const char* desc = isTrailer ? trailAccShort[accIdx[b]] : dataAccShort[accIdx[b]];
                const char* col  = isTrailer ? YELLOW : isValue ? CYAN : GREEN;
                std::cout << GRAY << "[" << (int)accC1[b] << (int)accC2[b] << (int)accC3[b] << "] "
                          << RESET << col << desc << RESET;
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

    constexpr const char* RED     = "\033[91m";
    constexpr const char* GREEN   = "\033[92m";
    constexpr const char* YELLOW  = "\033[93m";
    constexpr const char* CYAN    = "\033[96m";
    constexpr const char* MAGENTA = "\033[95m";
    constexpr const char* GRAY    = "\033[90m";
    constexpr const char* BOLD    = "\033[1m";
    constexpr const char* RESET   = "\033[0m";

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

    const char* typeColor = isMfr ? MAGENTA : isTrailer ? YELLOW : isValue ? CYAN : GREEN;
    const char* typeLabel = isMfr     ? "Manufacturer Block  [read-only]" :
                            isTrailer ? "Sector Trailer" :
                            isValue   ? "Value Block" :
                                        "Data Block";

    std::cout << "[+] S" << sector << "/B" << relBlock
              << "  abs=" << absBlock << "  "
              << typeColor << BOLD << "[" << typeLabel << "]" << RESET << "\n";

    std::cout << "    ";
    if (isMfr)
    {
        printGroup(0, 3, CYAN);    std::cout << "  ";
        printGroup(4, 15, YELLOW);
    }
    else if (isTrailer)
    {
        printGroup(0, 5, RED);     std::cout << "  ";
        printGroup(6, 9, YELLOW);  std::cout << "  ";
        printGroup(10, 15, CYAN);
    }
    else if (isValue)
    {
        printGroup(0, 3, CYAN);    std::cout << "  ";
        printGroup(4, 7, GRAY);    std::cout << "  ";
        printGroup(8, 11, CYAN);   std::cout << "  ";
        printGroup(12, 15, YELLOW);
    }
    else
    {
        printGroup(0, 7, GREEN);   std::cout << "  ";
        printGroup(8, 15, GREEN);
    }
    std::cout << "\n";

    if (isMfr)
    {
        std::cout << "    " << CYAN   << "NUID    " << RESET << ": " << CYAN;
        for (int i = 0; i < 4;  ++i) std::cout << hx(d[i]) << (i < 3  ? " " : "");
        std::cout << RESET << "\n";

        std::cout << "    " << YELLOW << "Mfr Data" << RESET << ": " << YELLOW;
        for (int i = 4; i < 16; ++i) std::cout << hx(d[i]) << (i < 15 ? " " : "");
        std::cout << RESET << "\n";
    }
    else if (isTrailer)
    {
        std::cout << "    " << RED << "KeyA    " << RESET
                  << ": " << RED << "(hidden by IC)\n" << RESET;

        const bool valid =
            ((d[6] & 0x0F) == ((~d[7] >> 4) & 0x0F)) &&
            ((d[6] >>  4)  == ((~d[8])       & 0x0F)) &&
            ((d[7] & 0x0F) == ((~d[8] >> 4)  & 0x0F));

        std::cout << "    " << YELLOW << "AccBits " << RESET << ": ";

        if (!valid)
        {
            std::cout << RED << BOLD << "INVALID  ⚠ settore potenzialmente bloccato!\n" << RESET;
        }
        else
        {
            std::cout << YELLOW << hx(d[6]) << " " << hx(d[7]) << " " << hx(d[8]) << RESET
                      << "  UserByte=" << CYAN << hx(d[9]) << RESET << "\n";

            static const char* dataAcc[8] = {
                /*000*/ "transport   r/w/inc/dec : KeyA|B",
                /*001*/ "value (nr)  r+dec       : KeyA|B  (non-rechargeable)",
                /*010*/ "read-only   r           : KeyA|B",
                /*011*/ "r/w KeyB    r/w         : KeyB",
                /*100*/ "r/w         r: KeyA|B   w: KeyB",
                /*101*/ "read KeyB   r           : KeyB",
                /*110*/ "value       r+dec: KeyA|B  w+inc: KeyB",
                /*111*/ "blocked     no access"
            };
            static const char* trailAcc[8] = {
                /*000*/ "KeyB readable : w-KeyA=A  acc-r=A  keyB=rw-A",
                /*001*/ "transport     : acc=rw-A  keyB=rw-A",
                /*010*/ "              : acc-r=A  keyB=r-A  (no writes)",
                /*011*/ "              : w-KeyA=B  acc=rw-B  keyB=w-B",
                /*100*/ "              : w-KeyA=B  acc-r=A|B  keyB=w-B",
                /*101*/ "              : acc=rw-B",
                /*110*/ "write-protect : acc-r=A|B",
                /*111*/ "locked        : acc-r=A|B"
            };

            for (int b = 0; b < 4; ++b)
            {
                const uint8_t c1  = (d[7] >> (4 + b)) & 1;
                const uint8_t c2  = (d[8] >>       b)  & 1;
                const uint8_t c3  = (d[8] >> (4 + b)) & 1;
                const uint8_t idx = (c1 << 2) | (c2 << 1) | c3;
                const char*  desc = (b == 3) ? trailAcc[idx] : dataAcc[idx];

                std::cout << "    " << YELLOW
                          << "B" << b << (b == 3 ? " (trailer)" : "          ")
                          << RESET << ": "
                          << "[" << (int)c1 << (int)c2 << (int)c3 << "]  "
                          << GRAY << desc << RESET << "\n";
            }
        }

        std::cout << "    " << CYAN << "KeyB    " << RESET << ": " << CYAN;
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

        std::cout << "    " << CYAN   << "Value   " << RESET << ": "
                  << CYAN << std::dec << val << RESET
                  << "  " << GRAY << hexVal.str() << RESET << "\n";

        std::cout << "    " << YELLOW << "Address " << RESET << ": "
                  << YELLOW << std::dec << static_cast<int>(d[12]) << RESET
                  << "  " << GRAY << hexAdr.str() << RESET << "\n";
    }
}

// ---------------------------------------------------------------------------
// cmdDumpFile
//
// Sintassi: dump [-k <keyfile>] [-f mct|bin]
//
// Legge tutti i 64 blocchi (16 settori × 4 blocchi) autenticando ogni settore
// con le chiavi disponibili. Salva in dumps/<NUID>.<fmt>.
//
// Formato MCT (MIFARE Classic Tool — default):
//   +Sector: N
//   <32 hex chars>   ← un blocco per riga
//   --------------------------------  ← blocco non leggibile
//
// Formato BIN:
//   1024 byte grezzi (64 blocchi × 16 byte).
//   Blocchi non letti → 16 byte 0x00.
// ---------------------------------------------------------------------------
void CommandParser::cmdDumpFile(std::istringstream& args)
{
    std::string keyFile = "keys/found.keys";
    std::string fmt = "mct";

    std::string tok;
    while (args >> tok)
    {
        if (tok == "-k" && args >> tok) keyFile = tok;
        else if (tok == "-f" && args >> tok) fmt = tok;
    }

    if (fmt != "mct" && fmt != "bin")
    {
        std::cout << "[!] Formato non valido. Usa: -f mct (default) o -f bin\n";
        return;
    }

    // -------------------------------------------------------------------------
    // NUID dal Manufacturer Block (S0/B0) → nome file
    // -------------------------------------------------------------------------
    std::string uidStr;

    if (autoAuth(0, keyFile))
    {
        auto resp = m_mifare->readBlock(0, 0);
        if (resp.success && resp.data.size() >= 4)
        {
            std::ostringstream ss;
            for (int i = 0; i < 4; ++i)
                ss << std::uppercase << std::hex
                   << std::setw(2) << std::setfill('0') << (int)resp.data[i];
            uidStr = ss.str();
        }
    }

    if (uidStr.empty())
    {
        // Fallback: timestamp UNIX se S0/B0 non è leggibile
        std::ostringstream ss;
        ss << "UNKNOWN_" << std::dec << static_cast<long>(std::time(nullptr));
        uidStr = ss.str();
    }

    // -------------------------------------------------------------------------
    // Crea cartella dumps/
    // -------------------------------------------------------------------------
    namespace fs = std::filesystem;
    try { fs::create_directories("dumps"); }
    catch (const std::exception& e)
    {
        std::cout << "[-] Impossibile creare la cartella dumps/: " << e.what() << "\n";
        return;
    }

    const std::string filename = "dumps/" + uidStr + "." + fmt;

    // -------------------------------------------------------------------------
    // Lettura di tutti i 64 blocchi
    // -------------------------------------------------------------------------
    struct BlockData { bool ok = false; std::vector<uint8_t> data; };
    std::vector<std::vector<BlockData>> mem(
        MifareClassic::SECTORS,
        std::vector<BlockData>(MifareClassic::BLOCKS_PER_SECTOR));

    int nOk = 0, nFail = 0;

    constexpr const char* GREEN = "\033[92m";
    constexpr const char* RED = "\033[91m";
    constexpr const char* GRAY = "\033[90m";
    constexpr const char* CYAN = "\033[96m";
    constexpr const char* BOLD = "\033[1m";
    constexpr const char* RESET = "\033[0m";

    auto secStr = [](int s) -> std::string {
        std::ostringstream ss;
        ss << std::dec << std::setw(2) << std::setfill('0') << s;
        return ss.str();
        };

    std::cout << "\n" << BOLD << "Dump " << MifareClassic::SECTORS
        << " settori → " << filename << RESET << "\n\n";

    for (int s = 0; s < MifareClassic::SECTORS; ++s)
    {
        const bool authed = autoAuth(s, keyFile);

        std::cout << "  S" << secStr(s) << "  ";

        if (!authed)
        {
            std::cout << RED << "[----] non autenticato" << RESET << "\n";
            nFail += MifareClassic::BLOCKS_PER_SECTOR;
            continue;
        }

        const auto& auth = m_mifare->getSectorAuth(s);
        std::cout << GREEN << "[Key" << auth.keyType << ": "
            << Hex::bytesToString(auth.key) << "]" << RESET << "  ";

        int secOk = 0;
        for (int b = 0; b < MifareClassic::BLOCKS_PER_SECTOR; ++b)
        {
            auto resp = m_mifare->readBlock(s, b);
            mem[s][b].ok = resp.success;
            mem[s][b].data = resp.data;
            if (resp.success) { nOk++; secOk++; }
            else                nFail++;
        }

        if (secOk == MifareClassic::BLOCKS_PER_SECTOR)
            std::cout << GREEN << "4/4 blocchi" << RESET << "\n";
        else
            std::cout << RED << secOk << "/4 blocchi" << RESET << "\n";
    }

    // -------------------------------------------------------------------------
    // Scrittura file
    // -------------------------------------------------------------------------
    if (fmt == "mct")
    {
        std::ofstream out(filename, std::ios::binary);
        if (!out)
        {
            std::cout << "[-] Impossibile aprire " << filename << " in scrittura\n";
            return;
        }

        auto blockHex = [](const std::vector<uint8_t>& d) -> std::string {
            std::ostringstream ss;
            for (uint8_t b : d)
                ss << std::uppercase << std::hex
                   << std::setw(2) << std::setfill('0') << (int)b;
            return ss.str();
        };

        for (int s = 0; s < MifareClassic::SECTORS; ++s)
        {
            out << "+Sector: " << s << "\n";
            const auto& auth = m_mifare->getSectorAuth(s);

            for (int b = 0; b < MifareClassic::BLOCKS_PER_SECTOR; ++b)
            {
                const auto& bd = mem[s][b];

                if (!bd.ok || bd.data.size() != 16)
                {
                    out << "--------------------------------\n";
                    continue;
                }

                std::vector<uint8_t> row = bd.data;

                // Sector trailer: l'IC maschera Key A come 0x00 nella risposta
                // READ BINARY (hardware by design, non bypassabile via PC/SC).
                // Key B può essere 0x00 se le AC non la rendono leggibile con
                // il tipo di chiave usato. Iniettare le chiavi note da m_authState
                // produce un dump completo e reimportabile in MCT / MifareOneTool.
                if (b == 3)
                {
                    if (auth.keyA.size() == 6)
                        std::copy(auth.keyA.begin(), auth.keyA.end(), row.begin());
                    if (auth.keyB.size() == 6)
                        std::copy(auth.keyB.begin(), auth.keyB.end(), row.begin() + 10);
                }

                out << blockHex(row) << "\n";
            }
        }
    }
    else  // bin
    {
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

                // Inizializza a zero: blocchi non letti → 16 byte 0x00
                std::vector<uint8_t> row(16, 0x00);
                if (bd.ok && bd.data.size() == 16)
                    row = bd.data;

                // Stessa iniezione chiavi del formato MCT
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
    }

    std::cout << "\n" << GREEN << "[+]" << RESET
        << " Salvato: " << CYAN << filename << RESET << "\n";
    std::cout << "    Blocchi letti: " << GREEN << nOk << "/64" << RESET
        << "  Non letti: " << (nFail > 0 ? RED : GRAY) << nFail << RESET
        << "\n\n";
}

// ---------------------------------------------------------------------------
// cmdWrite
//
// Sintassi: write -s <sector> -b <block> -d <32 hex chars>
//
// Scrive 16 byte su un blocco. Rifiuta S0/B0 (blocco produttore).
// Attenzione al sector trailer (blocco 3): contiene KeyA, Access Bits, KeyB.
// Una scrittura errata può rendere il settore inaccessibile.
// ---------------------------------------------------------------------------
void CommandParser::cmdWrite(std::istringstream& args)
{
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

    // Avviso per sector trailer (blocco 3): scrittura rischiosa
    if (relBlock == 3)
    {
        std::cout << "[!] ATTENZIONE: stai scrivendo sul sector trailer (blocco 3).\n"
                  << "    Contiene KeyA + Access Bits + KeyB. Una scrittura errata\n"
                  << "    puo' rendere il settore " << sector << " inaccessibile.\n"
                  << "    Continua? [s/N] ";
        std::string confirm;
        std::getline(std::cin, confirm);
        if (confirm != "s" && confirm != "S") { std::cout << "Annullato.\n"; return; }
    }

    // Parse hex data
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
//
// Loop principale:
//   1. Aspetta un tag (waitAndConnect)
//   2. Legge ATR e tipo carta
//   3. Crea un'istanza di MifareClassic (reset state ad ogni nuovo tag)
//   4. Shell interattiva finché il tag è presente
//   5. Alla rimozione del tag torna al punto 1
// ---------------------------------------------------------------------------
void CommandParser::run()
{
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

            // Ricontrolla dopo l'input: il tag potrebbe essere stato rimosso
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
            else if (cmd == "dump")         { cmdDumpFile(iss); }
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
