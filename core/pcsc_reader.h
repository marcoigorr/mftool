#pragma once
#include <winscard.h>
#include <string>
#include <vector>
#include <map>
#include <cstdint>

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

/**
 * @brief Informazioni di autenticazione per un settore MIFARE
 */
struct SectorAuth {
    bool authenticated;                      // true se l'autenticazione è riuscita
    std::vector<uint8_t> key;               // Chiave che ha funzionato
    uint8_t keyType;                        // 0x60 = Key A, 0x61 = Key B
    int keyIndex;                           // Indice della chiave nel vettore originale
    
    SectorAuth() : authenticated(false), keyType(0x60), keyIndex(-1) {}
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

    /**
     * @brief Aspetta che un tag venga avvicinato al lettore e tenta la connessione
     * 
     * @param readerName Nome del lettore da monitorare
     * @param timeoutSeconds Timeout in secondi (0 = nessun timeout, attesa infinita)
     * @return true se il tag è stato rilevato e connesso con successo, false in caso di timeout
     */
    bool waitAndConnect(const std::string& readerName, int timeoutSeconds = 0);

    /**
     * @brief Restituisce informazioni sul tag attualmente connesso
     * 
     * @return Struttura CardInfo contenente nome lettore, ATR e stato del tag
     */
    CardInfo getCardInfo();

    /**
     * @brief Trasmette un comando APDU al tag e riceve la risposta
     * 
     * @param command Comando APDU da inviare (formato vettore di bytes)
     * @return Risposta del tag incluso status word (SW1 SW2)
     */
    std::vector<uint8_t> transmit(const std::vector<uint8_t>& command);

    // ========== MIFARE Classic Operations ==========

    /**
     * @brief Carica una chiave di autenticazione nella memoria volatile del lettore ACR122U
     * 
     * @param keyNumber Slot di memoria dove salvare la chiave (0x00-0x01)
     * @param key Chiave MIFARE di 6 bytes (Key A o Key B)
     * @return true se la chiave è stata caricata con successo, false altrimenti
     * 
     * @note Il lettore ACR122U supporta 2 slot per le chiavi (0x00 e 0x01)
     * @note La chiave viene salvata in memoria volatile e si perde alla disconnessione
     */
    bool loadAuthenticationKey(uint8_t keyNumber, const std::vector<uint8_t>& key);

    /**
     * @brief Autentica un blocco MIFARE Classic usando una chiave precedentemente caricata
     * 
     * @param blockNumber Numero del blocco da autenticare (0-63 per MIFARE 1K)
     * @param keyType Tipo di chiave: 0x60 per Key A, 0x61 per Key B
     * @param keyNumber Slot di memoria contenente la chiave (0x00-0x01)
     * @return true se l'autenticazione è riuscita, false altrimenti
     * 
     * @note L'autenticazione è valida per tutto il settore (4 blocchi)
     * @note Deve essere preceduta da loadAuthenticationKey()
     */
    bool authenticate(uint8_t blockNumber, uint8_t keyType, uint8_t keyNumber);

    /**
     * @brief Prova ad autenticare un blocco testando una lista di chiavi (Key A e Key B)
     * 
     * @param blockNumber Numero del blocco da autenticare (0-63 per MIFARE 1K)
     * @param keys Vettore di chiavi da provare
     * @return true se l'autenticazione è riuscita con almeno una chiave, false altrimenti
     * 
     * @note Prova prima tutte le Key A, poi tutte le Key B
     * @note Si ferma alla prima chiave che funziona
     */
    bool tryAuthenticate(uint8_t blockNumber, const std::vector<std::vector<uint8_t>>& keys);

    /**
     * @brief Autentica un singolo settore e memorizza le credenziali nella cache
     * 
     * @param sector Numero del settore da autenticare (0-15 per MIFARE 1K)
     * @param keys Vettore di chiavi da provare
     * @return true se l'autenticazione è riuscita, false altrimenti
     * 
     * @note Le credenziali vengono salvate nella mappa sectorAuthCache
     * @note Prova sia Key A che Key B per ogni chiave fornita
     */
    bool authenticateSector(uint8_t sector, const std::vector<std::vector<uint8_t>>& keys);

    /**
     * @brief Pre-autentica tutti i settori della carta e memorizza i risultati
     * 
     * @param keys Vettore di chiavi da provare
     * @return Numero di settori autenticati con successo
     * 
     * @note Popola la mappa sectorAuthCache con le credenziali trovate
     * @note Operazione lenta ma permette di velocizzare le letture successive
     * @note Utile per fare un "dump" veloce della carta
     */
    int authenticateAllSectors(const std::vector<std::vector<uint8_t>>& keys);

    /**
     * @brief Verifica se un settore è già stato autenticato
     * 
     * @param sector Numero del settore (0-15 per MIFARE 1K)
     * @return true se il settore è già autenticato, false altrimenti
     */
    bool isSectorAuthenticated(uint8_t sector) const;

    /**
     * @brief Ottiene le informazioni di autenticazione per un settore
     * 
     * @param sector Numero del settore (0-15 per MIFARE 1K)
     * @return Struttura SectorAuth con le info di autenticazione
     */
    SectorAuth getSectorAuth(uint8_t sector) const;

    /**
     * @brief Pulisce la cache delle autenticazioni
     * 
     * @note Da chiamare quando si disconnette la carta o quando si vuole forzare una nuova scansione
     */
    void clearAuthCache();

    /**
     * @brief Legge 16 bytes da un blocco MIFARE Classic
     * 
     * @param blockNumber Numero del blocco da leggere (0-63 per MIFARE 1K)
     * @return Vettore di 16 bytes contenente i dati letti, vuoto in caso di errore
     * 
     * @note Se il settore è già autenticato, riusa le credenziali dalla cache
     * @note Altrimenti prova ad autenticare usando tutte le chiavi disponibili
     */
    std::vector<uint8_t> readBlock(uint8_t blockNumber);

    /**
     * @brief Scrive 16 bytes in un blocco MIFARE Classic
     * 
     * @param blockNumber Numero del blocco da scrivere (0-63 per MIFARE 1K)
     * @param data Vettore di esattamente 16 bytes da scrivere
     * @return true se la scrittura è riuscita, false altrimenti
     * 
     * @note Se il settore è già autenticato, riusa le credenziali dalla cache
     * @note ATTENZIONE: Non scrivere mai sul blocco 0 (contiene UID e manufacturer data)
     * @note ATTENZIONE: Fare attenzione ai blocchi trailer (ultimi di ogni settore) che contengono le chiavi
     */
    bool writeBlock(uint8_t blockNumber, const std::vector<uint8_t>& data);

    /**
     * @brief Legge tutti i blocchi di un settore MIFARE Classic (64 bytes totali)
     * 
     * @param sector Numero del settore da leggere (0-15 per MIFARE 1K)
     * @return Vettore di 64 bytes contenente i 4 blocchi del settore, vuoto in caso di errore
     * 
     * @note Richiede che il settore sia già autenticato con authenticateSector() o authenticateAllSectors()
     * @note Se il settore non è autenticato, ritorna un vettore vuoto
     */
    std::vector<uint8_t> readSector(uint8_t sector);

    /**
     * @brief Legge tutti i blocchi di un settore MIFARE Classic con autenticazione automatica
     * 
     * @param sector Numero del settore da leggere (0-15 per MIFARE 1K)
     * @param keys Vettore di chiavi da provare per l'autenticazione
     * @return Vettore di 64 bytes contenente i 4 blocchi del settore, vuoto in caso di errore
     * 
     * @note Autentica automaticamente il settore se non è già stato fatto
     */
    std::vector<uint8_t> readSectorWithAuth(uint8_t sector, const std::vector<std::vector<uint8_t>>& keys);

private:
    SCARDCONTEXT context;
    SCARDHANDLE cardHandle;
    DWORD activeProtocol;
    
    // Cache delle autenticazioni per settore
    std::map<uint8_t, SectorAuth> sectorAuthCache;
    
    // Helper: converte numero blocco in numero settore
    uint8_t blockToSector(uint8_t blockNumber) const { return blockNumber / 4; }
};