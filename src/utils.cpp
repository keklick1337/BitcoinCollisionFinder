// (c) Vladislav Tislenko (keklick1337), 19 Dec 2024
// utils.cpp
// Implementation of utility functions such as private key generation.

#include "utils.h"

void generate_privkey(std::mt19937_64 &rng, uint8_t priv[32], secp256k1_context *ctx) {
    do {
        for (int i=0;i<32;i++) priv[i]=(uint8_t)(rng() & 0xFF);
    } while(!secp256k1_ec_seckey_verify(ctx, priv));
}