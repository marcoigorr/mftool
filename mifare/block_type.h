/**
 * @file block_type.h
 * @brief Rilevamento e classificazione del tipo di blocco MIFARE Classic.
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
 * @brief Tipi di blocco MIFARE Classic 1K.
 */
enum class BlockType
{
    Manufacturer, ///< Blocco 0 del settore 0 (solo lettura, contiene UID e dati produttore)
    Trailer,      ///< Blocco 3 di ogni settore (chiavi e access bits)
    Value,        ///< Blocco dati in formato value (struttura ridondante con indirizzo)
    Data          ///< Blocco dati generico
};

/**
 * @brief Determina il tipo di un blocco MIFARE dato il contesto e il contenuto.
 *
 * @param sector   Settore (0-15).
 * @param relBlock Blocco relativo al settore (0-3).
 * @param data     16 byte del blocco.
 * @return Tipo del blocco.
 */
BlockType detectBlockType(int sector, int relBlock, const std::vector<uint8_t>& data);

/**
 * @brief Restituisce l'etichetta testuale del tipo di blocco.
 *
 * @param type Tipo del blocco.
 * @return Stringa descrittiva (es. "Sector Trailer", "Value Block").
 */
const char* blockTypeLabel(BlockType type);