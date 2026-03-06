#pragma once
#include "../core/pcsc_reader.h"
#include <memory>
#include <string>
#include <vector>

class CommandParser {
public:
    CommandParser();
    ~CommandParser();

    void run();

private:
    std::unique_ptr<PCSCReader> reader;
    std::vector<std::vector<uint8_t>> keys; 

    bool initializeReader();
    void showHelp() const;
    
    /**
     * @brief Stampa i dati di un blocco in formato leggibile (hex + ASCII)
     * 
     * @param blockNumber Numero del blocco
     * @param data Dati del blocco (16 bytes)
     * 
     * Esempio output:
     * Block 04: FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF  |................|
     */
    void printBlockData(uint8_t blockNumber, const std::vector<uint8_t>& data);

    // Command handlers
    void handleAuth();
    void handleStatus();
    void handleInfo();
    void handleRead(const std::string& line);
    void handleWrite(const std::string& line);
    void handleDump(const std::string& line);
    void handleDumpAll();
};
