//
// Created by ohayo on 2023/7/16.
//

#include "lockbox_md5.h"
#include "string.h"

#define abs(x) ((x)<0 ? (-x):(x))
#define F(X, Y, Z) ((X)&(Y)|(~X)&(Z))
#define G(X, Y, Z) ((X)&(Z)|(Y)&(~Z))
#define H(X, Y, Z) ((X)^(Y)^(Z))
#define I(X, Y, Z) ((Y)^((X)|(~Z)))
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

static const md5_byte pad[64] = {
        0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

void md5_init(md5_state *st) {
    st->abcd[0] = 0x67452301;
    st->abcd[1] = 0xefcdab89;
    st->abcd[2] = 0x98badcfe;
    st->abcd[3] = 0x10325476;
}

//完成一次轮运算
void md5_process(const md5_word *X, md5_state *st){
    md5_word a = st->abcd[0];
    md5_word b = st->abcd[1];
    md5_word c = st->abcd[2];
    md5_word d = st->abcd[3];

    md5_word t = 0;

#define SET(a, b, c, d, k, s, Ti)\
  t = a + F(b,c,d) + X[k] + Ti;\
  a = ROTATE_LEFT(t, s) + b
    SET(a, b, c, d, 0, 7, T1);
    SET(d, a, b, c, 1, 12, T2);
    SET(c, d, a, b, 2, 17, T3);
    SET(b, c, d, a, 3, 22, T4);
    SET(a, b, c, d, 4, 7, T5);
    SET(d, a, b, c, 5, 12, T6);
    SET(c, d, a, b, 6, 17, T7);
    SET(b, c, d, a, 7, 22, T8);
    SET(a, b, c, d, 8, 7, T9);
    SET(d, a, b, c, 9, 12, T10);
    SET(c, d, a, b, 10, 17, T11);
    SET(b, c, d, a, 11, 22, T12);
    SET(a, b, c, d, 12, 7, T13);
    SET(d, a, b, c, 13, 12, T14);
    SET(c, d, a, b, 14, 17, T15);
    SET(b, c, d, a, 15, 22, T16);
#undef SET

#define SET(a, b, c, d, k, s, Ti)\
  t = a + G(b,c,d) + X[k] + Ti;\
  a = ROTATE_LEFT(t, s) + b
    /* Do the following 16 operations. */
    SET(a, b, c, d, 1, 5, T17);
    SET(d, a, b, c, 6, 9, T18);
    SET(c, d, a, b, 11, 14, T19);
    SET(b, c, d, a, 0, 20, T20);
    SET(a, b, c, d, 5, 5, T21);
    SET(d, a, b, c, 10, 9, T22);
    SET(c, d, a, b, 15, 14, T23);
    SET(b, c, d, a, 4, 20, T24);
    SET(a, b, c, d, 9, 5, T25);
    SET(d, a, b, c, 14, 9, T26);
    SET(c, d, a, b, 3, 14, T27);
    SET(b, c, d, a, 8, 20, T28);
    SET(a, b, c, d, 13, 5, T29);
    SET(d, a, b, c, 2, 9, T30);
    SET(c, d, a, b, 7, 14, T31);
    SET(b, c, d, a, 12, 20, T32);
#undef SET

#define SET(a, b, c, d, k, s, Ti)\
  t = a + H(b,c,d) + X[k] + Ti;\
  a = ROTATE_LEFT(t, s) + b
    /* Do the following 16 operations. */
    SET(a, b, c, d, 5, 4, T33);
    SET(d, a, b, c, 8, 11, T34);
    SET(c, d, a, b, 11, 16, T35);
    SET(b, c, d, a, 14, 23, T36);
    SET(a, b, c, d, 1, 4, T37);
    SET(d, a, b, c, 4, 11, T38);
    SET(c, d, a, b, 7, 16, T39);
    SET(b, c, d, a, 10, 23, T40);
    SET(a, b, c, d, 13, 4, T41);
    SET(d, a, b, c, 0, 11, T42);
    SET(c, d, a, b, 3, 16, T43);
    SET(b, c, d, a, 6, 23, T44);
    SET(a, b, c, d, 9, 4, T45);
    SET(d, a, b, c, 12, 11, T46);
    SET(c, d, a, b, 15, 16, T47);
    SET(b, c, d, a, 2, 23, T48);
#undef SET

#define SET(a, b, c, d, k, s, Ti)\
  t = a + I(b,c,d) + X[k] + Ti;\
  a = ROTATE_LEFT(t, s) + b
    /* Do the following 16 operations. */
    SET(a, b, c, d, 5, 4, T33);
    SET(d, a, b, c, 8, 11, T34);
    SET(c, d, a, b, 11, 16, T35);
    SET(b, c, d, a, 14, 23, T36);
    SET(a, b, c, d, 1, 4, T37);
    SET(d, a, b, c, 4, 11, T38);
    SET(c, d, a, b, 7, 16, T39);
    SET(b, c, d, a, 10, 23, T40);
    SET(a, b, c, d, 13, 4, T41);
    SET(d, a, b, c, 0, 11, T42);
    SET(c, d, a, b, 3, 16, T43);
    SET(b, c, d, a, 6, 23, T44);
    SET(a, b, c, d, 9, 4, T45);
    SET(d, a, b, c, 12, 11, T46);
    SET(c, d, a, b, 15, 16, T47);
    SET(b, c, d, a, 2, 23, T48);
#undef SET

    st->abcd[0] += a;
    st->abcd[1] += b;
    st->abcd[2] += c;
    st->abcd[3] += d;
}

void md5_compute_txt(const char *txt, uint64_t len,md5_state *st) {
    uint8_t buf[64];
    uint64_t cur = len;
    md5_init(st);

    while(cur>=64){
        memset(buf,0,64);
        memcpy(buf,txt,64);
        md5_process((md5_word *) buf,st);
        cur -= 64;
        txt+=64;
    }
    //a block is 64byte,448bit = 56byte,64bit = 8byte
    uint64_t len_bit = len*8;

    //if data = 0byte,then padding = 56byte + 8byte len
    //if data = 56byte,then padding = 64byte + 8byte len
    //if data = 1byte,then padding = 55byte + 8byte len.
    memset(buf,0,64);
    memcpy(buf,txt,cur);
    if(cur<56){
        memcpy(buf+cur,pad,56 - cur);
        *(uint64_t*)&buf[56] = len_bit;
        md5_process((md5_word *) buf,st);
    }else{
        memcpy(buf+cur,pad,64 - cur);
        md5_process((md5_word *) buf,st);
        memset(buf,0,64);
        *(uint64_t*)&buf[56] = len_bit;
        md5_process((md5_word *) buf,st);
    }
}