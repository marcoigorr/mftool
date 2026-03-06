#pragma once
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cctype>

class Hex
{
public:

    /**
     * @brief Converte array byte in stringa esadecimale
     * 
     * @param bytes Vettore di bytes da convertire
     * @return Stringa esadecimale con spazi tra i bytes (es. "FF A0 3C")
     * 
     * @note Formato uppercase con padding a 2 caratteri per byte
     */
    static std::string bytesToString(const std::vector<uint8_t>& bytes) {
        std::stringstream ss;
        ss << std::uppercase << std::hex;
        for (size_t i = 0; i < bytes.size(); i++) {
            if (i > 0) ss << " ";  // Aggiungi spazio tra i byte
            ss << std::setw(2) << std::setfill('0') << (int)bytes[i];
        }
        return ss.str();
    }

    /**
     * @brief Converte stringa esadecimale in array byte
     * 
     * @param hexString Stringa esadecimale (con o senza spazi)
     * @return Vettore di bytes, vuoto se la stringa non è valida
     * 
     * @note Accetta formati: "FFAA3C", "FF AA 3C", "ff aa 3c"
     * @note Gli spazi e caratteri whitespace vengono automaticamente rimossi
     * @note La stringa deve contenere un numero pari di caratteri hex
     * 
     * Esempi:
     * - "FFFFFFFFFFFF" → {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
     * - "FF AA 3C"     → {0xFF, 0xAA, 0x3C}
     * - "A0A1A2"       → {0xA0, 0xA1, 0xA2}
     */
    static std::vector<uint8_t> stringToBytes(const std::string& hexString) {
        std::vector<uint8_t> bytes;
        
        // Rimuove tutti gli spazi e caratteri whitespace
        std::string cleanHex;
        for (char c : hexString) {
            if (!std::isspace(static_cast<unsigned char>(c))) {
                cleanHex += c;
            }
        }

        // Verifica che la lunghezza sia pari
        if (cleanHex.length() % 2 != 0) {
            return std::vector<uint8_t>();  // Errore: numero dispari di caratteri
        }

        // Verifica che contenga solo caratteri esadecimali
        for (char c : cleanHex) {
            if (!std::isxdigit(static_cast<unsigned char>(c))) {
                return std::vector<uint8_t>();  // Errore: carattere non hex
            }
        }

        // Converte ogni coppia di caratteri hex in un byte
        for (size_t i = 0; i < cleanHex.length(); i += 2) {
            std::string byteString = cleanHex.substr(i, 2);
            uint8_t byte = static_cast<uint8_t>(std::stoi(byteString, nullptr, 16));
            bytes.push_back(byte);
        }

        return bytes;
    }

    /**
     * @brief Converte un singolo byte in stringa esadecimale
     * 
     * @param byte Byte da convertire
     * @return Stringa di 2 caratteri hex (es. "FF", "0A")
     */
    static std::string byteToString(uint8_t byte) {
        std::stringstream ss;
        ss << std::uppercase << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
        return ss.str();
    }

    /**
     * @brief Verifica se una stringa è valida esadecimale
     * 
     * @param hexString Stringa da verificare
     * @return true se la stringa contiene solo caratteri hex validi (ignora spazi)
     */
    static bool isValidHex(const std::string& hexString) {
        for (char c : hexString) {
            if (!std::isspace(static_cast<unsigned char>(c)) && 
                !std::isxdigit(static_cast<unsigned char>(c))) {
                return false;
            }
        }
        return true;
    }
};
