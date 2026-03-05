#pragma once
#include <cstdint>

class Endian
{
public:

    /*
    littleToInt32()

    Converte 4 byte little endian
    in int32.
    */
    static int32_t littleToInt32(uint8_t b0, uint8_t b1, uint8_t b2, uint8_t b3)
    {
        return (b3 << 24) | (b2 << 16) | (b1 << 8) | b0;
    }
};
