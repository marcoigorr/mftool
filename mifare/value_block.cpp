/**
 * @file value_block.cpp
 * @brief Implementazione della costruzione del Value Block MIFARE Classic.
 */
#include "value_block.h"


std::array<uint8_t, 16> ValueBlock::create(int32_t value, uint8_t address)
{
    std::array<uint8_t, 16> block{};

    block[0] = value & 0xFF;
    block[1] = (value >> 8) & 0xFF;
    block[2] = (value >> 16) & 0xFF;
    block[3] = (value >> 24) & 0xFF;

    block[4] = ~block[0];
    block[5] = ~block[1];
    block[6] = ~block[2];
    block[7] = ~block[3];

    block[8] = block[0];
    block[9] = block[1];
    block[10] = block[2];
    block[11] = block[3];

    block[12] = address;
    block[13] = ~address;
    block[14] = address;
    block[15] = ~address;

    return block;
}