#pragma once
#include <array>
#include <cstdint>

class ValueBlock
{
public:

    /*
    create()

    value : valore intero
    address : indirizzo blocco

    Restituisce struttura MIFARE Value Block
    (16 byte con ridondanza e complementi).
    */
    static std::array<uint8_t, 16> create(int32_t value, uint8_t address);
};
