#include "mifare_classic.h"
#include "../utils/logger.h"
#include "../utils/hex.h"
#include <fstream>
#include <algorithm>
#include <cctype>

// ---------------------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------------------
MifareClassic::MifareClassic(PCSCReader& reader)
    : m_reader(reader)
{
    // m_authState è inizializzato con valid=false per tutti i 16 settori
}

// ---------------------------------------------------------------------------
// toAbsBlock
//
// MIFARE Classic 1K: 16 settori x 4 blocchi = 64 blocchi totali.
// Esempio: settore 3, blocco relativo 2 → blocco assoluto 14.
// ---------------------------------------------------------------------------
int MifareClassic::toAbsBlock(int sector, int relBlock)
{
    return sector * 4 + relBlock;
}

// ---------------------------------------------------------------------------
// loadKeys
//
// Legge un file .keys (una chiave per riga, 12 hex chars = 6 byte).
// Ignora righe vuote e commenti (#). Chiavi duplicate vengono incluse.
// ---------------------------------------------------------------------------
std::vector<std::vector<uint8_t>> MifareClassic::loadKeys(const std::string& path)
{
    std::vector<std::vector<uint8_t>> keys;

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
        if (line.size() != 12)              continue;

        std::vector<uint8_t> key;
        bool valid = true;
        for (size_t i = 0; i < 12; i += 2)
        {
            try   { key.push_back(static_cast<uint8_t>(std::stoul(line.substr(i, 2), nullptr, 16))); }
            catch (...) { valid = false; break; }
        }

        if (valid && key.size() == 6)
        {
            keys.push_back(key);
            Logger::debug("Loaded key from file: " + Hex::bytesToString(key));
        }
    }

    Logger::debug("Loaded " + std::to_string(keys.size()) + " key(s) from " + path);
    return keys;
}

// ---------------------------------------------------------------------------
// authenticate
//
// Esegue LOAD KEY + GENERAL AUTHENTICATE e aggiorna m_authState solo
// in caso di successo. Unico punto di accesso all'APDU di autenticazione.
// ---------------------------------------------------------------------------
bool MifareClassic::authenticate(int sector, const std::vector<uint8_t>& key, char keyType)
{
    uint8_t keyTypeByte = (keyType == 'B') ? KEY_TYPE_B : KEY_TYPE_A;

    Logger::debug("AUTH S" + std::to_string(sector)
                  + " Key" + (keyTypeByte == KEY_TYPE_B ? "B" : "A")
                  + " [" + Hex::bytesToString(key) + "]");

    // Step 1: LOAD KEY (FF 82 00 00 06 [key 6B])
    auto loadResp = m_reader.transmitAPDU(
        PCSCReader::buildAPDU(0xFF, 0x82, 0x00, 0x00, key)
    );
    if (!loadResp.success)
    {
        Logger::debug("LOAD KEY failed: " + loadResp.errorMessage);
        return false;
    }

    // Step 2: GENERAL AUTHENTICATE (FF 86 00 00 05 [01 00 block type slot])
    const int absBlock = toAbsBlock(sector, 0);
    const std::vector<uint8_t> authData = {
        0x01, 0x00,
        static_cast<uint8_t>(absBlock),
        keyTypeByte,
        0x00
    };

    auto authResp = m_reader.transmitAPDU(
        PCSCReader::buildAPDU(0xFF, 0x86, 0x00, 0x00, authData)
    );

    if (authResp.success)
    {
        auto& a   = m_authState[sector];
        a.valid   = true;
        a.keyType = keyType;
        a.key     = key;
        if (keyType == 'A') a.keyA = key;
        else                a.keyB = key;
    }
    return authResp.success;
}

// ---------------------------------------------------------------------------
// tryAuthenticate
//
// Attacco a dizionario su un singolo settore.
// Strategia: prova tutte le chiavi con KeyA, poi tutte con KeyB.
// Si ferma al primo successo.
// ---------------------------------------------------------------------------
bool MifareClassic::tryAuthenticate(int sector, const std::vector<std::vector<uint8_t>>& keys)
{
    for (char kt : { 'A', 'B' })
        for (const auto& key : keys)
            if (authenticate(sector, key, kt))
                return true;

    return false;
}

// ---------------------------------------------------------------------------
// reAuth  (private)
//
// Riautentica il settore usando le credenziali memorizzate in m_authState.
// Chiamato automaticamente da readBlock/writeBlock su SW 69 82.
// ---------------------------------------------------------------------------
bool MifareClassic::reAuth(int sector)
{
    const auto& auth = m_authState[sector];
    if (!auth.valid && auth.keyA.empty() && auth.keyB.empty()) return false;

    Logger::debug("reAuth S" + std::to_string(sector)
                  + " Key" + auth.keyType + "...");

    // 1. Prova il tipo/chiave attivo
    if (!auth.key.empty() && authenticate(sector, auth.key, auth.keyType))
        return true;

    // 2. Fallback all'altro tipo memorizzato
    if (auth.keyType == 'A' && auth.hasKeyB())
    {
        Logger::debug("reAuth S" + std::to_string(sector)
                      + ": KeyA failed, trying stored KeyB");
        return authenticate(sector, auth.keyB, 'B');
    }
    if (auth.keyType == 'B' && auth.hasKeyA())
    {
        Logger::debug("reAuth S" + std::to_string(sector)
                      + ": KeyB failed, trying stored KeyA");
        return authenticate(sector, auth.keyA, 'A');
    }

    return false;
}

// ---------------------------------------------------------------------------
// switchKeyType
//
// Commuta la sessione al tipo richiesto usando la chiave gia' scoperta.
// Utile quando un blocco e' accessibile solo con un tipo specifico.
// ---------------------------------------------------------------------------
bool MifareClassic::switchKeyType(int sector, char keyType)
{
    const auto& auth = m_authState[sector];
    const std::vector<uint8_t>& targetKey = (keyType == 'B') ? auth.keyB : auth.keyA;

    if (targetKey.empty())
    {
        Logger::debug("switchKeyType S" + std::to_string(sector)
                      + ": Key" + keyType + " non ancora scoperta");
        return false;
    }

    return authenticate(sector, targetKey, keyType);
}

// ---------------------------------------------------------------------------
// isAuthenticated / getSectorAuth
// ---------------------------------------------------------------------------
bool MifareClassic::isAuthenticated(int sector) const
{
    return (sector >= 0 && sector < SECTORS) && m_authState[sector].valid;
}

const SectorAuth& MifareClassic::getSectorAuth(int sector) const
{
    static const SectorAuth empty{};
    if (sector < 0 || sector >= SECTORS) return empty;
    return m_authState[sector];
}

// ---------------------------------------------------------------------------
// readBlock
//
// READ BINARY (FF B0 00 [absBlock] 10): legge 16 byte dal blocco.
// Se SW = 69 82 (security status not satisfied = sessione RF scaduta),
// esegue una riautenticazione automatica e riprova una volta.
// ---------------------------------------------------------------------------
APDUResponse MifareClassic::readBlock(int sector, int relBlock)
{
    int absBlock = toAbsBlock(sector, relBlock);

    auto resp = m_reader.transmitAPDU(
        PCSCReader::buildAPDU(0xFF, 0xB0, 0x00, static_cast<uint8_t>(absBlock), {}, 0x10)
    );

    // ACR122U può restituire 69 82 (security status) oppure 63 00 (operation
    // failed) per un settore la cui sessione RF è scaduta. Gestiamo entrambi.
    const bool needsReAuth = !resp.success &&
        ((resp.sw1 == 0x69 && resp.sw2 == 0x82) ||
         (resp.sw1 == 0x63 && resp.sw2 == 0x00));

    if (needsReAuth)
    {
        if (reAuth(sector))
        {
            resp = m_reader.transmitAPDU(
                PCSCReader::buildAPDU(0xFF, 0xB0, 0x00, static_cast<uint8_t>(absBlock), {}, 0x10)
            );
        }
    }

    return resp;
}

// ---------------------------------------------------------------------------
// writeBlock
//
// UPDATE BINARY (FF D6 00 [absBlock] 10 [data 16B]): scrive 16 byte.
// Rifiuta il blocco S0/B0 (dati produttore, read-only sulla carta).
// Auto-riautentica su SW 69 82 come readBlock.
// ---------------------------------------------------------------------------
APDUResponse MifareClassic::writeBlock(int sector, int relBlock, const std::vector<uint8_t>& data)
{
    if (sector == 0 && relBlock == 0)
    {
        APDUResponse err;
        err.errorMessage = "Manufacturer block (S0/B0) is read-only on MIFARE Classic";
        return err;
    }

    int absBlock = toAbsBlock(sector, relBlock);

    auto resp = m_reader.transmitAPDU(
        PCSCReader::buildAPDU(0xFF, 0xD6, 0x00, static_cast<uint8_t>(absBlock), data)
    );

    const bool needsReAuth = !resp.success &&
        ((resp.sw1 == 0x69 && resp.sw2 == 0x82) ||
         (resp.sw1 == 0x63 && resp.sw2 == 0x00));

    if (needsReAuth)
    {
        if (reAuth(sector))
        {
            resp = m_reader.transmitAPDU(
                PCSCReader::buildAPDU(0xFF, 0xD6, 0x00, static_cast<uint8_t>(absBlock), data)
            );
        }
    }

    return resp;
}