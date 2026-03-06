#pragma once
#include <memory>
#include <string>
#include <vector>
#include <cstdint>

class PCSCReader;

class CommandParser {
public:
    CommandParser();
    ~CommandParser();

    void run();

private:
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

    std::unique_ptr<PCSCReader> reader;
};
