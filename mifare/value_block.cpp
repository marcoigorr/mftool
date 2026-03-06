#include "value_block.h"

/**
 * @brief Crea un Value Block MIFARE Classic valido
 * 
 * Un Value Block è un formato speciale di 16 bytes utilizzato per memorizzare
 * valori interi con ridondanza per garantire l'integrità dei dati.
 * 
 * Struttura del Value Block:
 * - Bytes 0-3:   Valore (little-endian, signed 32-bit)
 * - Bytes 4-7:   Valore invertito (complemento a uno)
 * - Bytes 8-11:  Valore duplicato (copia di bytes 0-3)
 * - Bytes 12-15: Indirizzo [addr, ~addr, addr, ~addr]
 * 
 * @param value Il valore intero da memorizzare (range: -2,147,483,648 to 2,147,483,647)
 * @param address L'indirizzo del blocco (tipicamente il numero del blocco stesso, 0-255)
 * 
 * @return Un array di 16 bytes contenente il Value Block formattato correttamente
 * 
 * @note Il formato con ridondanza permette al lettore di verificare la validità del blocco
 *       prima di eseguire operazioni di incremento/decremento
 */
std::array<uint8_t, 16> ValueBlock::create(int32_t value, uint8_t address)
{
    std::array<uint8_t, 16> block{};

    // Bytes 0-3: Valore in formato little-endian (LSB first)
    block[0] = value & 0xFF;                 // Byte meno significativo
    block[1] = (value >> 8) & 0xFF;          // Secondo byte
    block[2] = (value >> 16) & 0xFF;         // Terzo byte
    block[3] = (value >> 24) & 0xFF;         // Byte più significativo

    // Bytes 4-7: Complemento a uno del valore (per verifica integrità)
    block[4] = ~block[0];
    block[5] = ~block[1];
    block[6] = ~block[2];
    block[7] = ~block[3];

    // Bytes 8-11: Copia del valore originale (ulteriore ridondanza)
    block[8] = block[0];
    block[9] = block[1];
    block[10] = block[2];
    block[11] = block[3];

    // Bytes 12-15: Indirizzo del blocco alternato con il suo complemento
    block[12] = address;                     // Indirizzo originale
    block[13] = ~address;                    // Complemento dell'indirizzo
    block[14] = address;                     // Indirizzo duplicato
    block[15] = ~address;                    // Complemento duplicato

    return block;
}