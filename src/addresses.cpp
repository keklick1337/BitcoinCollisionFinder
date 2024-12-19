// (c) Vladislav Tislenko (keklick1337), 19 Dec 2024
// addresses.cpp
// Implementation of address generation, hashing, encoding, and related functions.

#include "addresses.h"
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <cstring>
#include <string>
#include <vector>

static const char* BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
static const char* BECH32_ALPHABET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

// Base58
void base58_encode(const uint8_t* in, size_t inlen, char* out) {
    int zeroCount=0;
    while (zeroCount<(int)inlen && in[zeroCount]==0) zeroCount++;
    int size = (int)(inlen*138/100+1);
    unsigned char* buf = (unsigned char*)malloc(size);
    memset(buf,0,size);
    for (size_t i=0;i<inlen;i++){
        int carry = in[i];
        for (int j=size-1;j>=0;j--){
            carry += 256*buf[j];
            buf[j]=(unsigned char)(carry%58);
            carry/=58;
        }
    }
    int k=0; while(k<size && buf[k]==0) k++;
    int pos=0;
    for (int i=0;i<zeroCount;i++) out[pos++]='1';
    for (;k<size;k++) out[pos++]=BASE58_ALPHABET[buf[k]];
    out[pos]='\0';
    free(buf);
}

// Hashes
void sha256(const uint8_t *data,size_t len,uint8_t out[32]) {
    SHA256(data,len,out);
}

void hash160(const uint8_t *data,size_t len,uint8_t out[20]) {
    uint8_t sha[32];
    SHA256(data,len,sha);
    RIPEMD160(sha,32,out);
}

void double_sha256(const uint8_t *data,size_t len,uint8_t out[32]) {
    uint8_t tmp[32];
    SHA256(data,len,tmp);
    SHA256(tmp,32,out);
}

// WIF
void wif_from_privkey(const uint8_t priv[32],char wif_out[128]) {
    uint8_t ext[34];
    ext[0]=0x80;
    memcpy(ext+1,priv,32);
    ext[33]=0x01;
    uint8_t checksum[32];
    double_sha256(ext,34,checksum);
    uint8_t wif_bytes[38];
    memcpy(wif_bytes,ext,34);
    memcpy(wif_bytes+34,checksum,4);
    base58_encode(wif_bytes,38,wif_out);
}

// P2PKH
void p2pkh_address_from_pubkey(const uint8_t* pub,size_t pub_len,char addr_out[128]) {
    uint8_t h160[20];
    hash160(pub,pub_len,h160);
    uint8_t vh[21]; vh[0]=0x00;
    memcpy(vh+1,h160,20);
    uint8_t checksum[32];
    double_sha256(vh,21,checksum);
    uint8_t addr_bytes[25];
    memcpy(addr_bytes,vh,21);
    memcpy(addr_bytes+21,checksum,4);
    base58_encode(addr_bytes,25,addr_out);
}

// bech32 helpers
static int bech32_polymod(const int values[], size_t length) {
    uint32_t chk = 1;
    static const uint32_t GEN[5] = {
        0x3b6a57b2UL,0x26508e6dUL,0x1ea119faUL,0x3d4233ddUL,0x2a1462b3UL
    };
    for (size_t i=0; i<length; i++) {
        uint32_t top = chk >> 25;
        chk = (chk & 0x1ffffff) << 5 ^ values[i];
        for (int j=0; j<5; j++) {
            if ((top >> j) & 1) chk ^= GEN[j];
        }
    }
    return (int)chk;
}

static void bech32_hrp_expand(const char* hrp, std::vector<int> &dest) {
    size_t hrp_len = strlen(hrp);
    dest.resize(hrp_len*2+1);
    for (size_t i=0;i<hrp_len;i++) dest[i] = (unsigned char)(hrp[i]) >> 5;
    dest[hrp_len]=0;
    for (size_t i=0;i<hrp_len;i++) dest[hrp_len+1+i] = (unsigned char)(hrp[i]) & 31;
}

bool bech32_encode(char* output, const char* hrp, const unsigned char* data, size_t data_len) {
    std::vector<int> hrp_expand;
    bech32_hrp_expand(hrp, hrp_expand);
    std::vector<int> values;
    values.insert(values.end(), hrp_expand.begin(), hrp_expand.end());
    for (size_t i=0; i<data_len; i++)
        values.push_back(data[i]);

    for (int i=0; i<6; i++) values.push_back(0);

    int polymod = bech32_polymod(values.data(), values.size()) ^ 1;
    std::vector<int> checksum(6);
    for (int i=0; i<6; i++) {
        checksum[i] = (polymod >> (5*(5 - i))) & 31;
    }

    size_t hrp_len = strlen(hrp);
    strcpy(output, hrp);
    output[hrp_len] = '1';

    for (size_t i=0; i<data_len; i++)
        output[hrp_len+1+i] = BECH32_ALPHABET[data[i]];

    for (int i=0; i<6; i++)
        output[hrp_len+1+data_len+i] = BECH32_ALPHABET[checksum[i]];

    output[hrp_len+1+data_len+6] = '\0';
    return true;
}

bool convert_bits(unsigned char* out, size_t* outlen, int tobits, const unsigned char* in, size_t inlen, int frombits, bool pad) {
    uint32_t val = 0;
    int bits = 0;
    uint32_t maxv = (1 << tobits) - 1;
    size_t j=0;
    for (size_t i=0;i<inlen;i++) {
        unsigned int value = in[i];
        if (value >> frombits) {
            return false;
        }
        val = (val << frombits) | value;
        bits += frombits;
        while (bits >= tobits) {
            bits -= tobits;
            out[j++] = (unsigned char)((val >> bits) & maxv);
        }
    }

    if (pad) {
        if (bits > 0) {
            out[j++] = (unsigned char)((val << (tobits - bits)) & maxv);
        }
    } else if (bits >= frombits || ((val << (tobits - bits)) & maxv)) {
        return false;
    }

    *outlen = j;
    return true;
}

void p2wpkh_address_from_pubkey(const uint8_t* pub,size_t pub_len,char addr_out[128]) {
    uint8_t h160[20];
    hash160(pub,pub_len,h160);
    unsigned char data5[65]; 
    data5[0]=0;
    size_t data5_len=0;
    if(!convert_bits(data5+1,&data5_len,5,h160,20,8,false)) {
        addr_out[0]='\0'; 
        return;
    }
    data5_len += 1;
    if(!bech32_encode(addr_out,"bc",data5,data5_len)) {
        addr_out[0]='\0';
    }
}

void p2wpkh_p2sh_address_from_pubkey(const uint8_t* pub,size_t pub_len,char addr_out[128]) {
    uint8_t h160_pub[20];
    hash160(pub,pub_len,h160_pub);
    uint8_t redeem[22];
    redeem[0]=0x00;
    redeem[1]=0x14;
    memcpy(redeem+2,h160_pub,20);
    uint8_t h160[20];
    hash160(redeem,22,h160);
    uint8_t vh[21]; vh[0]=0x05;
    memcpy(vh+1,h160,20);
    uint8_t checksum[32];
    double_sha256(vh,21,checksum);
    uint8_t addr_bytes[25];
    memcpy(addr_bytes,vh,21);
    memcpy(addr_bytes+21,checksum,4);
    base58_encode(addr_bytes,25,addr_out);
}

#include <secp256k1.h>
void generate_all_addresses_from_priv(const uint8_t priv[32], secp256k1_context* ctx, 
                                      std::string &p2pkh_wif, std::string &p2pkh_addr, 
                                      std::string &p2wpkh_p2sh_wif, std::string &p2wpkh_p2sh_addr,
                                      std::string &p2wpkh_wif, std::string &p2wpkh_addr) {
    secp256k1_pubkey pubkey;
    secp256k1_ec_pubkey_create(ctx,&pubkey,priv);
    uint8_t pub[33];
    size_t pub_len=33;
    secp256k1_ec_pubkey_serialize(ctx,pub,&pub_len,&pubkey,SECP256K1_EC_COMPRESSED);

    char wif_c[128]; 
    wif_from_privkey(priv,wif_c);
    std::string base_wif = wif_c;

    if (enable_p2pkh) {
        char addr_c[128];
        p2pkh_address_from_pubkey(pub,pub_len,addr_c);
        p2pkh_wif = "p2pkh:" + base_wif;
        p2pkh_addr = addr_c;
    } else {
        p2pkh_wif = "";
        p2pkh_addr = "";
    }

    if (enable_p2wpkh_p2sh) {
        char addr_c[128];
        p2wpkh_p2sh_address_from_pubkey(pub,pub_len,addr_c);
        p2wpkh_p2sh_wif = "p2wpkh-p2sh:" + base_wif;
        p2wpkh_p2sh_addr = addr_c;
    } else {
        p2wpkh_p2sh_wif = "";
        p2wpkh_p2sh_addr = "";
    }

    if (enable_p2wpkh) {
        char addr_c[128];
        p2wpkh_address_from_pubkey(pub,pub_len,addr_c);
        p2wpkh_wif = "p2wpkh:" + base_wif;
        p2wpkh_addr = addr_c;
    } else {
        p2wpkh_wif = "";
        p2wpkh_addr = "";
    }
}