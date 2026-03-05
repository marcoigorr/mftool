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

class PCSCReader {
public:
    PCSCReader();
    ~PCSCReader();

    void establishContext();
    void releaseContext();

    std::vector<std::string> listReaders();
    bool connect(const std::string& readerName);
    void disconnect();

    /*
    waitAndConnect()

    Aspetta che un tag venga avvicinato al lettore: tenta la connessione.
    Ritorna true quando un tag è rilevato.
    */
    bool waitAndConnect(const std::string& readerName, int timeoutSeconds = 0);

    /*
    getCardInfo()

    Restituisce informazioni del tag rilevato.
    */
    CardInfo getCardInfo();

    std::vector<uint8_t> transmit(const std::vector<uint8_t>& command);

private:
    SCARDCONTEXT context;
    SCARDHANDLE cardHandle;
    DWORD activeProtocol;
};