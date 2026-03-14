/**
 * @file access_bits.h
 * @brief Decodifica e tabelle descrittive degli Access Bits MIFARE Classic.
 *
 * Copyright (C) 2026 Marco Petronio
 *
 * This file is part of mftool.
 *
 * mftool is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * mftool is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with mftool. If not, see <https://www.gnu.org/licenses/>.
 */
#pragma once
#include <vector>
#include <cstdint>

/**
 * @brief Access bits decodificati per tutti i 4 blocchi di un settore MIFARE Classic.
 *
 * Struttura del sector trailer (byte 6-8):
 *   B6[3:0] = ~C1[3:0]   B7[7:4] = C1[3:0]
 *   B6[7:4] = ~C2[3:0]   B8[3:0] = C2[3:0]
 *   B7[3:0] = ~C3[3:0]   B8[7:4] = C3[3:0]
 */
struct AccessBits
{
    bool    valid   = false;  ///< true se i 3 byte del trailer sono consistenti
    uint8_t c1[4]  = {};      ///< Bit C1 per blocco 0-3
    uint8_t c2[4]  = {};      ///< Bit C2 per blocco 0-3
    uint8_t c3[4]  = {};      ///< Bit C3 per blocco 0-3
    uint8_t idx[4] = {};      ///< Indice combinato (c1<<2|c2<<1|c3) per blocco 0-3

    /**
     * @brief Decodifica gli access bits dal sector trailer (16 byte).
     *
     * @param trailer 16 byte del sector trailer (blocco 3 del settore).
     * @return AccessBits popolato; valid=false se i byte sono inconsistenti.
     */
    static AccessBits decode(const std::vector<uint8_t>& trailer);

    /**
     * @brief Descrizione compatta per un blocco dati (usata nella vista tabella).
     * @param index Indice 0-7 (c1<<2|c2<<1|c3).
     */
    static const char* dataDescShort(uint8_t index);

    /**
     * @brief Descrizione compatta per il sector trailer (usata nella vista tabella).
     * @param index Indice 0-7.
     */
    static const char* trailerDescShort(uint8_t index);

    /**
     * @brief Descrizione estesa per un blocco dati (usata nella vista dettaglio).
     * @param index Indice 0-7.
     */
    static const char* dataDescFull(uint8_t index);

    /**
     * @brief Descrizione estesa per il sector trailer (usata nella vista dettaglio).
     * @param index Indice 0-7.
     */
    static const char* trailerDescFull(uint8_t index);

    };