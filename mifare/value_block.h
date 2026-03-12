/**
 * @file value_block.h
 * @brief Utilità per la costruzione di blocchi valore MIFARE Classic (Value Block).
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
#include <array>
#include <cstdint>

/**
 * @brief Genera blocchi valore nel formato MIFARE Classic.
 *
 * Un Value Block MIFARE è un blocco dati a 16 byte con struttura ridondante:
 *   - Byte  0-3  : valore (little-endian)
 *   - Byte  4-7  : complemento del valore
 *   - Byte  8-11 : valore (copia di controllo)
 *   - Byte 12,14 : indirizzo blocco
 *   - Byte 13,15 : complemento dell'indirizzo
 */
class ValueBlock
{
public:
    /**
     * @brief Costruisce un Value Block MIFARE Classic di 16 byte.
     *
     * Imposta valore, complemento e indirizzo secondo la specifica MIFARE.
     *
     * @param value   Valore intero con segno (32 bit) da memorizzare nel blocco.
     * @param address Indirizzo logico del blocco (1 byte), usato per le operazioni
     *                di incremento/decremento con restore.
     * @return Array di 16 byte nel formato Value Block MIFARE.
     */
    static std::array<uint8_t, 16> create(int32_t value, uint8_t address);
};
