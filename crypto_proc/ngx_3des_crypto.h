#ifndef _DES_CRYPTO_H
#define _DES_CRYPTO_H

#include <stdio.h>
#include <memory.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#define DES_LONG unsigned long
#define LEN_OF_KEY 24

#define ITERATIONS 16

#define c2l(c,l)        (l =((DES_LONG)(*((c)++)))    , \
l|=((DES_LONG)(*((c)++)))<< 8L, \
l|=((DES_LONG)(*((c)++)))<<16L, \
l|=((DES_LONG)(*((c)++)))<<24L)


#define l2c(l,c)        (*((c)++)=(unsigned char)(((l)     )&0xff), \
*((c)++)=(unsigned char)(((l)>> 8L)&0xff), \
*((c)++)=(unsigned char)(((l)>>16L)&0xff), \
*((c)++)=(unsigned char)(((l)>>24L)&0xff))

#define ROTATE(a,n)     (((a)>>(n))+((a)<<(32-(n))))

#define LOAD_DATA_tmp(a,b,c,d,e,f) LOAD_DATA(a,b,c,d,e,f,g)
#define LOAD_DATA(R,S,u,t,E0,E1,tmp) \
u=R^s[S  ]; \
t=R^s[S+1]

#define D_ENCRYPT(LL,R,S) {\
LOAD_DATA_tmp(R,S,u,t,E0,E1); \
t=ROTATE(t,4); \
LL^=\
TDES_SPtrans[0][(u>> 2L)&0x3f]^ \
TDES_SPtrans[2][(u>>10L)&0x3f]^ \
TDES_SPtrans[4][(u>>18L)&0x3f]^ \
TDES_SPtrans[6][(u>>26L)&0x3f]^ \
TDES_SPtrans[1][(t>> 2L)&0x3f]^ \
TDES_SPtrans[3][(t>>10L)&0x3f]^ \
TDES_SPtrans[5][(t>>18L)&0x3f]^ \
TDES_SPtrans[7][(t>>26L)&0x3f]; }

#define PERM_OP(a,b,t,n,m) ((t)=((((a)>>(n))^(b))&(m)),\
(b)^=(t),\
(a)^=((t)<<(n)))

#define IP(l,r) \
{ \
register DES_LONG tt; \
PERM_OP(r,l,tt, 4,0x0f0f0f0fL); \
PERM_OP(l,r,tt,16,0x0000ffffL); \
PERM_OP(r,l,tt, 2,0x33333333L); \
PERM_OP(l,r,tt, 8,0x00ff00ffL); \
PERM_OP(r,l,tt, 1,0x55555555L); \
}

#define FP(l,r) \
{ \
register DES_LONG tt; \
PERM_OP(l,r,tt, 1,0x55555555L); \
PERM_OP(r,l,tt, 8,0x00ff00ffL); \
PERM_OP(l,r,tt, 2,0x33333333L); \
PERM_OP(r,l,tt,16,0x0000ffffL); \
PERM_OP(l,r,tt, 4,0x0f0f0f0fL); \
}

//extern const DES_LONG TDES_SPtrans[8][64];         


#define HPERM_OP(a,t,n,m) ((t)=((((a)<<(16-(n)))^(a))&(m)),\
(a)=(a)^(t)^(t>>(16-(n))))


typedef unsigned char DES_cblock[8];
typedef /* const */ unsigned char const_DES_cblock[8];


typedef struct DES_ks {
union {
DES_cblock cblock;
/*
*           * make sure things are correct size on machines with 8 byte longs
*                     */
DES_LONG deslong[2];
} ks[16];
} DES_key_schedule;


# define DES_ENCRYPT     1
# define DES_DECRYPT     0



void DES_ecb3_encrypt(const_DES_cblock *input, DES_cblock *output,
DES_key_schedule *ks1, DES_key_schedule *ks2,
DES_key_schedule *ks3, int enc);


void TDES_encrypt1(DES_LONG *data, DES_key_schedule *ks, int enc);

void TDES_encrypt2(DES_LONG *data, DES_key_schedule *ks, int enc);

void TDES_encrypt3(DES_LONG *data, DES_key_schedule *ks1,
DES_key_schedule *ks2, DES_key_schedule *ks3);
void TDES_decrypt3(DES_LONG *data, DES_key_schedule *ks1,
DES_key_schedule *ks2, DES_key_schedule *ks3);

void TDES_set_key_unchecked(const_DES_cblock *key, DES_key_schedule *schedule);


#endif

