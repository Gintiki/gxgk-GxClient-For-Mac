#ifndef md5_INCLUDED
#define md5_INCLUDED

#include <stdint.h>//

/* POINTER defines a generic pointer type */
typedef unsigned char *POINTER;

/* UINT2 defines a two byte word */
typedef unsigned short int UINT2;

/* UINT4 defines a four byte word */
typedef unsigned long int UINT4;

typedef struct {
    uint32_t state[4];                                   /* state (ABCD) */
    uint32_t count[2];        /* number of bits, modulo 2^64 (lsb first) */
    unsigned char buffer[64];                         /* input buffer */
} MD5_CTX;

void MD5Init(MD5_CTX *);
void MD5Update(MD5_CTX *, unsigned char *, unsigned int);
void MD5Final(unsigned char[16], MD5_CTX *);
void hmac_md5(unsigned char* text, int text_len, unsigned char* key, int key_len, unsigned char* outPut);

#endif
