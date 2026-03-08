#pragma once
#include <winscard.h>
#include <string>
#include <vector>

// Se MAX_ATR_SIZE non è definito da winscard.h
#ifndef MAX_ATR_SIZE
#define MAX_ATR_SIZE 33
#endif

#ifndef MAX_READERNAME
#define MAX_READERNAME 256
#endif

struct CardInfo {
    std::string readerName;
    std::vector<uint8_t> atr;
    std::string cardState;
};

// Struttura per la risposta APDU
struct APDUResponse {
    std::vector<uint8_t> data;          // Payload di risposta (senza SW)
    bool                 success = false;
    uint8_t              sw1     = 0;   // Status Word byte 1
    uint8_t              sw2     = 0;   // Status Word byte 2
    std::string          errorMessage;  // Descrizione leggibile in caso di errore
};

class PCSCReader {
public:
    PCSCReader();
    ~PCSCReader();

    void establishContext();
    void releaseContext();

    std::vector<std::string> listReaders();

    /*
    waitAndConnect()

    Aspetta che un tag venga avvicinato al lettore: tenta la connessione.
    Ritorna true quando un tag è rilevato.
    */
    bool waitAndConnect(const std::string& readerName, int timeoutSeconds = 0);
    
    void disconnect();

    /*
    getCardInfo()

    Restituisce informazioni del tag rilevato.
    */
    CardInfo getCardInfo();

    // Trasmissione base (raw bytes)
    std::vector<uint8_t> transmit(const std::vector<uint8_t>& command);

    // Trasmissione con parsing automatico di SW1/SW2
    APDUResponse transmitAPDU(const std::vector<uint8_t>& command);

    // Helper per costruire comandi APDU
    static std::vector<uint8_t> buildAPDU(uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2,
                                          const std::vector<uint8_t>& data = {},
                                          uint8_t le = 0);

private:
    SCARDCONTEXT context;
    SCARDHANDLE cardHandle;
    DWORD activeProtocol;
};