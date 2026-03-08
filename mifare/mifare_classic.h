#pragma once
#include <vector>
#include <string>
#include <array>
#include <cstdint>
#include "../core/pcsc_reader.h"

// ---------------------------------------------------------------------------
// SectorAuth
//
// Credenziali di autenticazione memorizzate per un singolo settore.
// Usate per la riautenticazione automatica quando la sessione RF scade
// (SW 69 82 = security status not satisfied).
// ---------------------------------------------------------------------------
struct SectorAuth
{
    bool                 valid   = false;
    char                 keyType = 'A';   // tipo attivo per la sessione corrente
    std::vector<uint8_t> key;             // chiave attiva (per reAuth automatico)

    // Chiavi scoperte e verificate per tipo — persistenti indipendentemente
    // dalla sessione corrente. Popolate da authenticate() / tryAuthenticate().
    std::vector<uint8_t> keyA;            // Key A che ha funzionato su questo settore
    std::vector<uint8_t> keyB;            // Key B che ha funzionato su questo settore

    bool hasKeyA() const { return !keyA.empty(); }
    bool hasKeyB() const { return !keyB.empty(); }
};

// ---------------------------------------------------------------------------
// MifareClassic
//
// Operazioni di alto livello su carte MIFARE Classic 1K / 4K.
// Gestisce l'autenticazione per-settore, la riautenticazione automatica
// e l'accesso in lettura/scrittura ai blocchi.
//
// Struttura MIFARE Classic 1K:
//   16 settori x 4 blocchi = 64 blocchi totali (0-63)
//   Ogni blocco = 16 byte
//   Blocco 3 di ogni settore = sector trailer (KeyA | Access Bits | KeyB)
//
// Autenticazione (CRYPTO1, 3-pass):
//   1. LOAD KEY       (FF 82) - carica la chiave nel reader (slot 0)
//   2. GENERAL AUTH   (FF 86) - autentica il settore sulla carta
//   La sessione è valida finché il campo RF rimane attivo.
//   Su SW 69 82, readBlock/writeBlock eseguono riautenticazione automatica.
//
// Riferimento APDU: ACR122U API v2.04
// ---------------------------------------------------------------------------
class MifareClassic
{
public:
    static constexpr int     SECTORS           = 16;
    static constexpr int     BLOCKS_PER_SECTOR = 4;
    static constexpr int     BLOCK_SIZE        = 16;
    static constexpr uint8_t KEY_TYPE_A        = 0x60;  // P2 per GENERAL AUTHENTICATE
    static constexpr uint8_t KEY_TYPE_B        = 0x61;

    explicit MifareClassic(PCSCReader& reader);

    // -------------------------------------------------------------------------
    // Authentication
    // -------------------------------------------------------------------------

    // Autentica il settore con la chiave specificata.
    // Aggiorna le credenziali memorizzate solo in caso di successo.
    bool authenticate(int sector, const std::vector<uint8_t>& key, char keyType = 'A');

    // Prova ogni chiave dalla lista, prima con KeyA poi con KeyB.
    // Si ferma al primo successo. Ideale per l'attacco a dizionario.
    bool tryAuthenticate(int sector, const std::vector<std::vector<uint8_t>>& keys);

    // True se esiste uno stato di autenticazione valido per il settore.
    bool isAuthenticated(int sector) const;

    // Restituisce le credenziali memorizzate (valido anche se valid=false).
    const SectorAuth& getSectorAuth(int sector) const;

    // Commuta il tipo attivo usando la chiave gia' scoperta per quel tipo.
    // Restituisce false se il tipo richiesto non e' ancora stato trovato.
    bool switchKeyType(int sector, char keyType);

    // -------------------------------------------------------------------------
    // Read / Write
    // -------------------------------------------------------------------------

    // READ BINARY (FF B0): legge 16 byte da un blocco.
    // Blocco relativo: 0-3 all'interno del settore.
    // Auto-riautentica su SW 69 82 usando le credenziali memorizzate.
    APDUResponse readBlock(int sector, int relBlock);

    // UPDATE BINARY (FF D6): scrive 16 byte su un blocco.
    // Rifiuta S0/B0 (blocco produttore, read-only su MIFARE Classic).
    // Auto-riautentica su SW 69 82 come readBlock.
    APDUResponse writeBlock(int sector, int relBlock, const std::vector<uint8_t>& data);

    // -------------------------------------------------------------------------
    // Static helpers
    // -------------------------------------------------------------------------

    // Blocco assoluto = settore * 4 + bloccoRelativo  (range: 0-63)
    static int toAbsBlock(int sector, int relBlock);

    // Carica chiavi da file .keys (una per riga, 12 hex chars = 6 byte).
    // Ignora righe vuote e righe che iniziano con '#'.
    static std::vector<std::vector<uint8_t>> loadKeys(const std::string& path);

private:
    PCSCReader&                      m_reader;
    std::array<SectorAuth, SECTORS>  m_authState;

    // Riautentica usando le credenziali già in m_authState (senza keyfile)
    bool reAuth(int sector);
};
