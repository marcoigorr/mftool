/**
 * @file hex.h
 * @brief Utilità per la conversione tra array di byte e rappresentazione esadecimale.
 */
#pragma once
#include <string>
#include <vector>
#include <array>
#include <cstdint>
#include <sstream>
#include <iomanip>

// Forward declaration
using MifareKey = std::array<uint8_t, 6>;

/**
 * @brief Funzioni statiche per la conversione esadecimale di byte.
 */
class Hex
{
public:
    /**
     * @brief Converte una stringa esadecimale in un array MifareKey (6 byte).
     *
     * La stringa può contenere spazi; deve rappresentare esattamente 6 byte (12 caratteri hex).
     *
     * @param hex Stringa esadecimale da convertire (es. "A0A1A2A3A4A5").
     * @return Array di 6 byte corrispondente alla chiave MIFARE.
     * @throws std::invalid_argument Se la stringa non è lunga 12 caratteri hex validi.
     */
    static MifareKey stringToBytes(const std::string& hex);

    /**
     * @brief Converte un array MifareKey in stringa esadecimale maiuscola.
     *
     * @param bytes Array di 6 byte da convertire.
     * @param withSpaces Se true, inserisce uno spazio tra ogni coppia di byte (default: true).
     * @return Stringa esadecimale uppercase (es. "A0 A1 A2 A3 A4 A5").
     */
    static std::string bytesToString(const MifareKey& bytes, bool withSpaces = true);

    /**
     * @brief Converte un vettore di byte in stringa esadecimale maiuscola.
     *
     * @param bytes Vettore di byte da convertire.
     * @param withSpaces Se true, inserisce uno spazio tra ogni coppia di byte (default: true).
     * @return Stringa esadecimale uppercase.
     */
    static std::string bytesToString(const std::vector<uint8_t>& bytes, bool withSpaces = true);
};

/**
 * @brief Converte un singolo byte in stringa esadecimale uppercase a 2 cifre.
 *
 * @param byte Byte da convertire.
 * @return Stringa di 2 caratteri hex uppercase (es. "0F").
 */
inline std::string toHex(uint8_t byte)
{
    std::ostringstream ss;
    ss << std::uppercase << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(byte);
    return ss.str();
}
