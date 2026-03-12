/**
 * @file atr_parser.h
 * @brief Parser per l'ATR (Answer To Reset) restituito da carte NFC/smartcard.
 */
#pragma once
#include <vector>
#include <string>
#include <cstdint>

/**
 * @brief Analizza l'ATR di una carta NFC per determinarne il tipo.
 */
class ATRParser {
public:
    /**
     * @brief Determina il tipo di carta dal suo ATR.
     *
     * Struttura ATR per carte ISO 14443-A (NXP) su ACR122U (20 byte):
     *   3B 8F 80 01 80 4F 0C A0 00 00 03 06 [D0..D6] [TCK]
     *
     * Il byte D2 (indice 14) identifica il tipo di carta:
     *   - 0x01 = MIFARE Classic 1K
     *   - 0x02 = MIFARE Classic 4K
     *   - 0x03 = MIFARE Ultralight / NTAG
     *   - 0x04 = MIFARE Classic Mini
     *   - 0x10 = MIFARE DESFire
     *
     * Riferimento: ACR122U Application Programming Interface V2.04.
     *
     * @param atr Vettore di byte contenente l'ATR della carta.
     * @return Stringa con il nome del tipo di carta, oppure "Unknown Card Type (ATR: ...)"
     *         se l'ATR non è riconosciuto.
     */
    static std::string getCardType(const std::vector<uint8_t>& atr);
};