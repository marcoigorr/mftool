#pragma once
#include <string>
#include <memory>
#include <vector>
#include <sstream>

class PCSCReader;
class MifareClassic;

// ---------------------------------------------------------------------------
// CommandParser
//
// Shell interattiva per operazioni su carte MIFARE Classic 1K via ACR122U.
// Gestisce il loop principale (attesa tag, comandi, rimozione tag) e
// delega le operazioni MIFARE alla classe MifareClassic.
// ---------------------------------------------------------------------------
class CommandParser
{
public:
    CommandParser();
    ~CommandParser();

    void run();
	void run2(); 

private:
    std::unique_ptr<PCSCReader>    m_reader;
    std::unique_ptr<MifareClassic> m_mifare;

    // -------------------------------------------------------------------------
    // Init / UI
    // -------------------------------------------------------------------------
    bool initializeReader();
    void showHelp() const;

    // -------------------------------------------------------------------------
    // Command handlers  (ogni handler riceve il resto della riga come stream)
    // -------------------------------------------------------------------------

    // read -s <settore 0-15> [-b <blocco 0-3>]
    //   Senza -b: tabella 4 blocchi con colori + colonna Access.
    //   Con -b:   decodifica dettagliata del singolo blocco.
    void cmdRead(std::istringstream& args);

    // dump
    //   Legge tutti i 64 blocchi e salva in dumps/Dump_<UID>.mfd.
    void cmdDumpFile();

    void cmdReadDump(std::istringstream& args);  // ← NUOVO

    // write -s <settore 0-15> -b <blocco 0-3> -d <32 hex chars>
    //   Scrive 16 byte. Auto-autentica tramite stato memorizzato o keyfile.
    void cmdWrite(std::istringstream& args);

    // tagid
    //   Legge il Manufacturer Block (S0/B0): NUID + manufacturer data.
    //   Autentica automaticamente il settore 0 con Key A (default FFFFFFFFFFFF).
    void cmdTagID();

    // authenticate -s <settore 0-15> [-k <keyfile>] [-t A|B]
    //   Autentica un singolo settore. Default: found.keys, prova entrambe le chiavi.
    void cmdAuthenticate(std::istringstream& args);

    // scan [-k <keyfile>]
    //   Prova tutti i 16 settori con tutte le chiavi del file (KeyA + KeyB).
    //   Mostra una tabella con le chiavi trovate per settore.
    void cmdScan(std::istringstream& args);

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    // Tenta l'autenticazione tramite stato memorizzato (ensureAuthenticated),
    // con fallback sulle chiavi in keys/found.keys.
    bool autoAuth(int sector, const std::string& keyFile = "keys/found.keys");

    // Decodifica SW1/SW2 in una stringa leggibile (MIFARE + ISO 7816).
    static std::string decodeSW(uint8_t sw1, uint8_t sw2);
};
