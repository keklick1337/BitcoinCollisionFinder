// (c) Vladislav Tislenko (keklick1337), 19 Dec 2024
// config.h
// This header provides global variables declarations.

#ifndef CONFIG_H
#define CONFIG_H

#include <string>
#include <unordered_set>

extern std::string out_file_name;
extern bool have_known;
extern bool test_mode;
extern bool enable_p2pkh;
extern bool enable_p2wpkh_p2sh;
extern bool enable_p2wpkh;

extern std::unordered_set<std::string> known_addresses_legacy;
extern std::unordered_set<std::string> known_addresses_bc1;

#endif
