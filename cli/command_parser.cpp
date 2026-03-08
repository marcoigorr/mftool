#include "command_parser.h"
#include "../core/pcsc_reader.h"
#include "../mifare/mifare_classic.h"
#include "../utils/logger.h"
#include "../utils/atr_parser.h"
#include "../utils/hex.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <cctype>

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
    std::cout << "  authenticate -s <settore> [-k <keyfile>] [-t A|B]\n";
    std::cout << "      Autentica un settore. Senza -t prova prima KeyA poi KeyB.\n\n";
    std::cout << "  read -s <settore> -b <blocco>\n";
    std::cout << "      Legge 16 byte (blocco 0-3; blocco 3 = sector trailer)\n\n";
    std::cout << "  write -s <settore> -b <blocco> -d <32 hex chars>\n";
    std::cout << "      Scrive 16 byte su un blocco autenticato\n";
    std::cout << "      Es: write -s 1 -b 0 -d 48656C6C6F000000000000000000000\n\n";
    std::cout << "  dump -s <settore>\n";
    std::cout << "      Mostra tutti i 4 blocchi del settore (hex + ASCII)\n\n";
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

    // ostringstream: non contamina lo stato di std::cout
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
// Sintassi: authenticate -s <sector> [-k <keyfile>] [-t A|B]
//
// Senza -t: prova prima KeyA poi KeyB (tryAuthenticate).
// Con -t A o -t B: prova solo il tipo specificato con tutte le chiavi.
// Default keyfile: keys/found.keys
// ---------------------------------------------------------------------------
void CommandParser::cmdAuthenticate(std::istringstream& args)
{
    int         sector  = -1;
    std::string keyFile = "keys/found.keys";
    char        keyType = '\0';   // '\0' = prova entrambe

    std::string token;
    while (args >> token)
    {
        if      (token == "-s" && args >> token) sector  = std::stoi(token);
        else if (token == "-k" && args >> token) keyFile = token;
        else if (token == "-t" && args >> token) keyType = (char)std::toupper(token[0]);
    }

    if (sector < 0 || sector > 15)
    {
        std::cout << "[!] Uso: authenticate -s <settore 0-15> [-k <keyfile>] [-t A|B]\n";
        return;
    }

    auto keys = MifareClassic::loadKeys(keyFile);
    if (keys.empty())
    {
        std::cout << "[!] Nessuna chiave valida in: " << keyFile << "\n";
        return;
    }

    bool ok = false;

    if (keyType == '\0')
    {
        // Nessun tipo specificato: prova entrambi (tryAuthenticate)
        ok = m_mifare->tryAuthenticate(sector, keys);
    }
    else
    {
        // Tipo specificato: prova solo quel tipo
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

    // Formato settore in ostringstream separato: evita che std::hex / std::left /
    // setfill('0') del loop contaminino il formato di 's' nel cout principale.
    auto secStr = [](int s) {
        std::ostringstream ss;
        ss << std::dec << std::setw(2) << std::setfill('0') << s;
        return ss.str();
    };

    // Padding a destra con spazi, senza toccare lo stato di cout
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

        // Ripristina KeyA come auth principale (usata da read/dump)
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
// Sintassi: read -s <sector> -b <block>
//
// Classifica il blocco e lo visualizza con colori e decodifica:
//
//   Manufacturer Block (S0/B0)
//     byte 0-3  [cyan]   : NUID
//     byte 4-15 [yellow] : Manufacturer Data
//
//   Sector Trailer (Brel=3)
//     byte 0-5  [red]    : Key A (sempre 0x00 in lettura, nascosta dall'IC)
//     byte 6-9  [yellow] : Access Bits (3 byte) + User Byte
//     byte 10-15[cyan]   : Key B
//     → decode dei 3 bit di accesso per ogni blocco del settore
//
//   Value Block (heuristica NXP §8.6.2.1: d[0-3]=V, d[4-7]=~V, d[8-11]=V, d[12]=A, d[13]=~A)
//     byte 0-3  [cyan]   : V
//     byte 4-7  [gray]   : ~V
//     byte 8-11 [cyan]   : V copy
//     byte 12-15[yellow] : Address
//     → decode del valore signed 32-bit e dell'indirizzo
//
//   Data Block
//     16 byte   [green]  : raw data
// ---------------------------------------------------------------------------
void CommandParser::cmdRead(std::istringstream& args)
{
    int sector = -1, relBlock = -1;
    std::string token;
    while (args >> token)
    {
        if      (token == "-s" && args >> token) sector   = std::stoi(token);
        else if (token == "-b" && args >> token) relBlock = std::stoi(token);
    }

    if (sector < 0 || sector > 15 || relBlock < 0 || relBlock > 3)
    {
        std::cout << "[!] Uso: read -s <settore 0-15> -b <blocco 0-3>\n";
        return;
    }

    if (!m_mifare->isAuthenticated(sector))
    {
        std::cout << "[!] Settore " << sector << " non autenticato. "
                  << "Esegui prima: authenticate -s " << sector << "\n";
        return;
    }

    auto resp = m_mifare->readBlock(sector, relBlock);
    if (!resp.success)
    {
        std::cout << "[-] Lettura fallita. " << decodeSW(resp.sw1, resp.sw2) << "\n";
        return;
    }

    const auto& d        = resp.data;
    const int   absBlock = MifareClassic::toAbsBlock(sector, relBlock);

    // -------------------------------------------------------------------------
    // ANSI colors
    // -------------------------------------------------------------------------
    constexpr const char* RED     = "\033[91m";
    constexpr const char* GREEN   = "\033[92m";
    constexpr const char* YELLOW  = "\033[93m";
    constexpr const char* CYAN    = "\033[96m";
    constexpr const char* MAGENTA = "\033[95m";
    constexpr const char* GRAY    = "\033[90m";
    constexpr const char* BOLD    = "\033[1m";
    constexpr const char* RESET   = "\033[0m";

    // -------------------------------------------------------------------------
    // Helpers locali
    // -------------------------------------------------------------------------
    // Formatta un byte come "A0" tramite ostringstream (non tocca stato cout)
    auto hx = [](uint8_t b) {
        std::ostringstream ss;
        ss << std::uppercase << std::hex << std::setw(2) << std::setfill('0') << (int)b;
        return ss.str();
    };

    // Stampa un gruppo di byte contigui [from, to] con un colore
    auto printGroup = [&](int from, int to, const char* color) {
        for (int i = from; i <= to; ++i)
        {
            std::cout << color << hx(d[i]) << RESET;
            if (i < to) std::cout << " ";
        }
    };

    // -------------------------------------------------------------------------
    // Classificazione blocco
    // -------------------------------------------------------------------------
    const bool isMfr     = (sector == 0 && relBlock == 0);
    const bool isTrailer = (relBlock == 3);

    // Value block: NXP §8.6.2.1
    bool isValue = false;
    if (!isMfr && !isTrailer && d.size() == 16)
    {
        isValue = true;
        for (int i = 0; i < 4 && isValue; ++i)
        {
            if (d[i] != d[i + 8])           isValue = false;  // V == V-copy
            if (d[i] != (uint8_t)~d[i + 4]) isValue = false;  // V == ~(~V)
        }
        if (d[12] != d[14])            isValue = false;  // A == A-copy
        if (d[12] != (uint8_t)~d[13]) isValue = false;  // A == ~(~A)
    }

    // -------------------------------------------------------------------------
    // Header
    // -------------------------------------------------------------------------
    const char* typeColor = isMfr ? MAGENTA : isTrailer ? YELLOW : isValue ? CYAN : GREEN;
    const char* typeLabel = isMfr     ? "Manufacturer Block  [read-only]" :
                            isTrailer ? "Sector Trailer" :
                            isValue   ? "Value Block" :
                                        "Data Block";

    std::cout << "[+] S" << sector << "/B" << relBlock
              << "  abs=" << absBlock << "  "
              << typeColor << BOLD << "[" << typeLabel << "]" << RESET << "\n";

    // -------------------------------------------------------------------------
    // Riga HEX colorata per campo
    // -------------------------------------------------------------------------
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

    // -------------------------------------------------------------------------
    // Decodifica per tipo
    // -------------------------------------------------------------------------
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
        // --- Key A (hidden) ---
        std::cout << "    " << RED << "KeyA    " << RESET
                  << ": " << RED << "(hidden by IC)\n" << RESET;

        // --- Access Bits ---
        // Validità: byte 6 contiene le copie invertite di C1 e C2
        // (NXP §8.7.1: "if format violation the whole sector is irreversibly blocked")
        const bool valid =
            ((d[6] & 0x0F) == ((~d[7] >> 4) & 0x0F)) &&   // ~C1 == ~C1 check
            ((d[6] >>  4)  == ((~d[8])       & 0x0F)) &&   // ~C2 == ~C2 check
            ((d[7] & 0x0F) == ((~d[8] >> 4)  & 0x0F));     // ~C3 == ~C3 check

        std::cout << "    " << YELLOW << "AccBits " << RESET << ": ";

        if (!valid)
        {
            std::cout << RED << BOLD << "INVALID  ⚠ settore potenzialmente bloccato!\n" << RESET;
        }
        else
        {
            std::cout << YELLOW << hx(d[6]) << " " << hx(d[7]) << " " << hx(d[8]) << RESET
                      << "  UserByte=" << CYAN << hx(d[9]) << RESET << "\n";

            // Descrizioni accesso per data block (C1 C2 C3) → indice = (c1<<2)|(c2<<1)|c3
            // Fonte: NXP MF1S50yyX/V1 datasheet Table 8
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
            // Descrizioni accesso per sector trailer (block 3)
            // Fonte: NXP MF1S50yyX/V1 datasheet Table 7
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
                // Estrai C1_b, C2_b, C3_b per il blocco b nel settore
                // NXP Figure 10:
                //   C1_b = bit (4+b) di byte 7
                //   C2_b = bit  b    di byte 8
                //   C3_b = bit (4+b) di byte 8
                const uint8_t c1  = (d[7] >> (4 + b)) & 1;
                const uint8_t c2  = (d[8] >>       b)  & 1;
                const uint8_t c3  = (d[8] >> (4 + b)) & 1;
                const uint8_t idx = (c1 << 2) | (c2 << 1) | c3;

                const char* desc = (b == 3) ? trailAcc[idx] : dataAcc[idx];

                std::cout << "    " << YELLOW
                          << "B" << b << (b == 3 ? " (trailer)" : "          ")
                          << RESET << ": "
                          << "[" << (int)c1 << (int)c2 << (int)c3 << "]  "
                          << GRAY << desc << RESET << "\n";
            }
        }

        // --- Key B ---
        std::cout << "    " << CYAN << "KeyB    " << RESET << ": " << CYAN;
        for (int i = 10; i < 16; ++i) std::cout << hx(d[i]) << (i < 15 ? " " : "");
        std::cout << RESET << "\n";
    }
    else if (isValue)
    {
        // Decode: V = little-endian signed 32-bit (NXP §8.6.2.1)
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

    if (!m_mifare->isAuthenticated(sector))
    {
        std::cout << "[!] Settore " << sector << " non autenticato. "
                  << "Esegui prima: authenticate -s " << sector << "\n";
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
// cmdDump
//
// Sintassi: dump -s <sector>
//
// Legge e stampa tutti i 4 blocchi del settore in formato tabellare.
// Usa MifareClassic::readBlock che gestisce la riautenticazione automatica.
// ---------------------------------------------------------------------------
void CommandParser::cmdDump(std::istringstream& args)
{
    int sector = -1;

    std::string token;
    while (args >> token)
        if (token == "-s" && args >> token) sector = std::stoi(token);

    if (sector < 0 || sector > 15)
    {
        std::cout << "[!] Uso: dump -s <settore 0-15>\n";
        return;
    }

    if (!m_mifare->isAuthenticated(sector))
    {
        std::cout << "[!] Settore " << sector << " non autenticato. "
                  << "Esegui prima: authenticate -s " << sector << "\n";
        return;
    }

    // ostringstream: non contamina lo stato di std::cout
    auto hx = [](uint8_t b) {
        std::ostringstream ss;
        ss << std::uppercase << std::hex << std::setw(2) << std::setfill('0') << (int)b;
        return ss.str();
    };

    const auto& auth = m_mifare->getSectorAuth(sector);
    std::cout << "\n[Sector " << sector << "] Key" << auth.keyType
              << ": " << Hex::bytesToString(auth.key) << "\n";
    std::cout << "  Blk  Abs  | 00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F | ASCII\n";
    std::cout << "  ---------   -----------------------------------------------   ----------------\n";

    for (int b = 0; b < MifareClassic::BLOCKS_PER_SECTOR; ++b)
    {
        int absBlock = MifareClassic::toAbsBlock(sector, b);
        auto resp    = m_mifare->readBlock(sector, b);

        std::cout << "  B" << b << " [" << hx(static_cast<uint8_t>(absBlock)) << "]  | ";

        if (!resp.success)
        {
            std::cout << "-- lettura fallita: " << decodeSW(resp.sw1, resp.sw2);
        }
        else
        {
            for (size_t i = 0; i < resp.data.size(); ++i)
            {
                if (i == 8) std::cout << " ";
                std::cout << hx(resp.data[i]) << " ";
            }
            std::cout << "| ";
            for (uint8_t byte : resp.data)
                std::cout << (std::isprint(byte) ? (char)byte : '.');
        }

        if (b == 3) std::cout << "  <- sector trailer";
        std::cout << "\n";
    }
    std::cout << "\n";
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
            else if (cmd == "dump")         { cmdDump(iss); }
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
