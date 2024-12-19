// (c) Vladislav Tislenko (keklick1337), 19 Dec 2024
// addresses.h
// This header declares functions for address generation, hashing, and encoding.
// It also provides external flags controlling which address types are generated.

#ifndef ADDRESSES_H
#define ADDRESSES_H

#include <cstdint>
#include <cstddef>
#include <string>
#include <secp256k1.h>

// Global flags to enable/disable address types
extern bool enable_p2pkh;
extern bool enable_p2wpkh_p2sh;
extern bool enable_p2wpkh;

// Base58
void base58_encode(const uint8_t* in, size_t inlen, char* out);

// Hash functions
void sha256(const uint8_t *data,size_t len,uint8_t out[32]);
void hash160(const uint8_t *data,size_t len,uint8_t out[20]);
void double_sha256(const uint8_t *data,size_t len,uint8_t out[32]);

// WIF
void wif_from_privkey(const uint8_t priv[32],char wif_out[128]);

// P2PKH
void p2pkh_address_from_pubkey(const uint8_t* pub,size_t pub_len,char addr_out[128]);

// bech32/convert_bits related
bool convert_bits(unsigned char* out, size_t* outlen, int tobits, const unsigned char* in, size_t inlen, int frombits, bool pad);
bool bech32_encode(char* output, const char* hrp, const unsigned char* data, size_t data_len);

// P2WPKH and P2WPKH-P2SH
void p2wpkh_address_from_pubkey(const uint8_t* pub,size_t pub_len,char addr_out[128]);
void p2wpkh_p2sh_address_from_pubkey(const uint8_t* pub,size_t pub_len,char addr_out[128]);

// Generate all addresses from a privkey
void generate_all_addresses_from_priv(const uint8_t priv[32], secp256k1_context* ctx,
                                      std::string &p2pkh_wif, std::string &p2pkh_addr, 
                                      std::string &p2wpkh_p2sh_wif, std::string &p2wpkh_p2sh_addr,
                                      std::string &p2wpkh_wif, std::string &p2wpkh_addr);

#endif