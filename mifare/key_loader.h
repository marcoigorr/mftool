#pragma once
#include <vector>
#include <string>
#include <cstdint>

/**
 * @brief Utility per il caricamento di chiavi MIFARE da file
 * 
 * Gestisce il parsing di file contenenti chiavi MIFARE Classic in formato esadecimale.
 * Supporta commenti (#) e righe vuote nel file delle chiavi.
 */
class MifareKeyLoader {
public:
    /**
     * @brief Carica chiavi MIFARE da un file di testo
     * 
     * Il file deve contenere chiavi in formato esadecimale (12 caratteri = 6 bytes).
     * Le righe che iniziano con '#' vengono ignorate come commenti.
     * Gli spazi bianchi vengono automaticamente rimossi.
     * 
     * Esempio di formato file:
     * ```
     * # Chiave di default MIFARE
     * FFFFFFFFFFFF
     * A0A1A2A3A4A5
     * # Altra chiave comune
     * D3F7D3F7D3F7
     * ```
     * 
     * @param filename Percorso del file contenente le chiavi
     * @return Vettore di chiavi, ogni chiave è un vettore di 6 bytes
     * 
     * @note Le chiavi non valide vengono silenziosamente ignorate
     */
    static std::vector<std::vector<uint8_t>> loadFromFile(const std::string& filename);

    /**
     * @brief Converte una stringa esadecimale in una chiave MIFARE
     * 
     * @param hexString Stringa esadecimale di 12 caratteri
     * @return Vettore di 6 bytes, vuoto se la stringa non è valida
     */
    static std::vector<uint8_t> parseKey(const std::string& hexString);
};