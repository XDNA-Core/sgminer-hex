#ifndef X16M_H
#define X16M_H

#include "miner.h"

#include <stdint.h>

enum 
{
  X16M_BLAKE = 0,
  X16M_BMW,
  X16M_GROESTL,
  X16M_JH,
  X16M_KECCAK,
  X16M_SKEIN,
  X16M_LUFFA,
  X16M_CUBEHASH,
  X16M_SHAVITE,
  X16M_SIMD,
  X16M_ECHO,
  X16M_HAMSI,
  X16M_FUGUE,
  X16M_SHABAL,
  X16M_WHIRLPOOL,
  X16M_SHA512,
  X16M_HASH_FUNC_COUNT
};

extern void x16m_regenhash(struct work *work);

static inline void x16m_getalgolist(const uint8_t* data, uint8_t *output)
{
	uint8_t *orig = output;

	for (int j = 0; j < X16M_HASH_FUNC_COUNT; j++) 
	{
		int b = (15 - j) >> 1;
		*output++ = (j & 1) ? data[b] & 0xF : data[b] >> 4;
	}
}

#endif
