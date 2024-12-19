// (c) Vladislav Tislenko (keklick1337), 19 Dec 2024
// config.cpp
// This file defines global variables declared in config.h.

#include "config.h"

std::string out_file_name = "out.list";
bool have_known = false;
bool test_mode = false;
bool enable_p2pkh = true;
bool enable_p2wpkh_p2sh = true;
bool enable_p2wpkh = true;

std::unordered_set<std::string> known_addresses_legacy;
std::unordered_set<std::string> known_addresses_bc1;