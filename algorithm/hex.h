#ifndef HEX_H
#define HEX_H

#include "miner.h"

#include <stdint.h>

enum 
{
  HEX_BLAKE = 0,
  HEX_BMW,
  HEX_GROESTL,
  HEX_JH,
  HEX_KECCAK,
  HEX_SKEIN,
  HEX_LUFFA,
  HEX_CUBEHASH,
  HEX_SHAVITE,
  HEX_SIMD,
  HEX_ECHO,
  HEX_HAMSI,
  HEX_FUGUE,
  HEX_SHABAL,
  HEX_WHIRLPOOL,
  HEX_SHA512,
  HEX_HASH_FUNC_COUNT
};

extern void hex_regenhash(struct work *work);

static inline void hex_getalgolist(const uint8_t* data, uint8_t *output)
{
	uint8_t *orig = output;

	for (int j = 0; j < HEX_HASH_FUNC_COUNT; j++) 
	{
		int b = (15 - j) >> 1;
		*output++ = (j & 1) ? data[b] & 0xF : data[b] >> 4;
	}
}

#endif
