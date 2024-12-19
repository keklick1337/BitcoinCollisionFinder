// (c) Vladislav Tislenko (keklick1337), 19 Dec 2024
// utils.h
// This header declares utility functions, such as private key generation.

#ifndef UTILS_H
#define UTILS_H

#include <random>
#include <cstdint>
#include <secp256k1.h>

void generate_privkey(std::mt19937_64 &rng, uint8_t priv[32], secp256k1_context *ctx);

#endif