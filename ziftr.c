/*
 * Copyright 2014 mkimid
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */
 /*
***** ZiftrCOIN Hashing Algo Module  by ocminer (admin at suprnova.cc)  ******
*/
/*
 * Further modified by Stephen Morse and Justin Wilcox
 */

#include "cpuminer-config.h"
#include "miner.h"

#include "hash-groestl.h"

#include <string.h>
#include <stdint.h>

#define USE_SPH_KECCAK 1     // Don't comment this out unless fixed for 80 byte input

#ifdef USE_SPH_SKEIN
#undef USE_SPH_SKEIN
#endif

#include "sph_keccak.h"

#include "algos/blake.c"

#include "algos/jh_sse2_opt64.h"

#include "algos/skein.c"
 
#define POK_BOOL_MASK 0x00008000
#define POK_DATA_MASK 0xFFFF0000

#if defined(__GNUC__)
      #define DATA_ALIGN16(x) x __attribute__ ((aligned(16)))
#else
      #define DATA_ALIGN16(x) __declspec(align(16)) x
#endif

// Pre-computed table of permutations
static const int arrOrder[][4] =
{
    {0, 1, 2, 3},
    {0, 1, 3, 2},
    {0, 2, 1, 3},
    {0, 2, 3, 1},
    {0, 3, 1, 2},
    {0, 3, 2, 1},
    {1, 0, 2, 3},
    {1, 0, 3, 2},
    {1, 2, 0, 3},
    {1, 2, 3, 0},
    {1, 3, 0, 2},
    {1, 3, 2, 0},
    {2, 0, 1, 3},
    {2, 0, 3, 1},
    {2, 1, 0, 3},
    {2, 1, 3, 0},
    {2, 3, 0, 1},
    {2, 3, 1, 0},
    {3, 0, 1, 2},
    {3, 0, 2, 1},
    {3, 1, 0, 2},
    {3, 1, 2, 0},
    {3, 2, 0, 1},
    {3, 2, 1, 0}
};

static inline void ziftr_blake(unsigned char *hash)
{
	#if !defined(USE_SPH_BLAKE) || !defined(USE_SPH_SKEIN)
    DATA_ALIGN16(size_t hashptr);
    DATA_ALIGN16(sph_u64 hashctA);
	#endif

	#if !defined(USE_SPH_BLAKE)
    DATA_ALIGN16(sph_u64 hashctB);
	#endif
	
	{
		#define hashbuf hash
		DECL_BLK;
		BLK_I;
		BLK_U;
		BLK_C;
		#undef hashbuf
	}
}

static inline void ziftr_groestl(unsigned char *hash)
{
	unsigned long long tmp[8] __attribute__((aligned(16)));
	
	hash_groestl(512, hash, 64 << 3, tmp);
    memcpy(hash, tmp, 64);
}

static inline void ziftr_jh(unsigned char *hash)
{
	#define hashbuf hash
	
	DECL_JH;
	JH_H;
	
	#undef hashbuf
}

static inline void ziftr_skein(unsigned char *hash)
{
	#define hashbuf hash
	
	#if !defined(USE_SPH_BLAKE) || !defined(USE_SPH_SKEIN)
    DATA_ALIGN16(size_t hashptr);
    DATA_ALIGN16(sph_u64 hashctA);
	#endif
	
	DECL_SKN;
	SKN_I;
	SKN_U;
	SKN_C;
	
	#undef hashbuf
}

static void ziftrhash(void *state, const void *input)
{
    DATA_ALIGN16(unsigned char hashbuf[128]);
    DATA_ALIGN16(unsigned char hash[128]);

#if !defined(USE_SPH_BLAKE) || !defined(USE_SPH_SKEIN)
    DATA_ALIGN16(size_t hashptr);
    DATA_ALIGN16(sph_u64 hashctA);
#endif

#if !defined(USE_SPH_BLAKE)
    DATA_ALIGN16(sph_u64 hashctB);
#endif

#ifdef USE_SPH_KECCAK
    sph_keccak512_context    ctx_keccak;
#endif

#ifdef USE_SPH_BLAKE
    sph_blake512_context     ctx_blake;
#endif

#ifdef USE_SPH_JH
    sph_jh512_context        ctx_jh;
#endif

#ifdef USE_SPH_SKEIN
    sph_skein512_context     ctx_skein;
#endif

#ifdef USE_SPH_KECCAK
    sph_keccak512_init(&ctx_keccak);
    sph_keccak512 (&ctx_keccak, input, 80);
    sph_keccak512_close(&ctx_keccak, (&hash));
#else
{
    // I believe this is optimized for 64 length input,
    // so probably won't work for zrc, since we use
    // input of length 80 here
    int i; 
    DECL_KEC;
    KEC_I;
    KEC_U;
    KEC_C;
}
#endif

    unsigned int nOrder = *(unsigned int *)(&hash) % 24;

    unsigned int i = 0;
	
    for(i = 0; i < 4; i++)
    {
		switch(arrOrder[nOrder][i])
		{
			case 0:
				ziftr_blake(hash);
				break;
			case 1:
				ziftr_groestl(hash);
				break;
			case 2:
				ziftr_jh(hash);
				break;
			case 3:
				ziftr_skein(hash);
				break;
		}
    }
    
	memcpy(state, hash, 32);
}

int scanhash_ziftr(int thr_id, uint32_t *pdata, const uint32_t *ptarget,
	uint32_t max_nonce, unsigned long *hashes_done)
{

	uint32_t hash[16] __attribute__((aligned(64)));
	uint32_t tmpdata[20] __attribute__((aligned(64)));

    const uint32_t version = pdata[0] & (~POK_DATA_MASK);
	const uint32_t first_nonce = pdata[19];
	uint32_t nonce = first_nonce;
 
	memcpy(tmpdata, pdata, 80);
 
	do {
		#define Htarg ptarget[7]
 
		tmpdata[0]  = version;
		tmpdata[19] = nonce;
		ziftrhash(hash, tmpdata);
		tmpdata[0] = version | (hash[0] & POK_DATA_MASK);
		ziftrhash(hash, tmpdata);
 
		if (hash[7] <= Htarg && fulltest(hash, ptarget))
		{
			pdata[0] = tmpdata[0];
			pdata[19] = nonce;
			*hashes_done = pdata[19] - first_nonce + 1;
			if (opt_debug)
				applog(LOG_INFO, "found nonce %x", nonce);

            return 1;
		}
		nonce++;
 
	} while (nonce < max_nonce && !work_restart[thr_id].restart);
 
	pdata[19] = nonce;
	*hashes_done = pdata[19] - first_nonce + 1;
	return 0;

}

