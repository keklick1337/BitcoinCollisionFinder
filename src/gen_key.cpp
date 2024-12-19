// (c) Vladislav Tislenko (keklick1337), 19 Dec 2024
// main_app.cpp
// This file contains the main entry point of the application, argument parsing,
// initialization of resources, thread management, and collision checks.
// Modified to separately count addresses starting with '1' (P2PKH) and '3' (P2SH).

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <vector>
#include <string>
#include <thread>
#include <mutex>
#include <random>
#include <fstream>
#include <unordered_set>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <secp256k1.h>

#include "addresses.h"
#include "utils.h"
#include "config.h"

static std::mutex out_file_mutex;
static std::ofstream out_file;
static std::atomic<long long> generated_count(0);

static void speed_reporter_thread(int update_interval_seconds) {
    using namespace std::chrono;
    auto start = steady_clock::now();
    long long prev_count = 0;
    while(!test_mode) {
        std::this_thread::sleep_for(std::chrono::seconds(update_interval_seconds));
        auto now = steady_clock::now();
        long long current = generated_count.load(std::memory_order_relaxed);
        long long diff = current - prev_count;
        prev_count = current;
        double rate = diff / (double)update_interval_seconds;
        std::string rate_str;
        if (rate>1e9) {
            rate_str = std::to_string(rate/1e9)+" Gaddr/s";
        } else if (rate>1e6) {
            rate_str = std::to_string(rate/1e6)+" Maddr/s";
        } else if (rate>1e3) {
            rate_str = std::to_string(rate/1e3)+" Kaddr/s";
        } else {
            rate_str = std::to_string(rate)+" addr/s";
        }
        fprintf(stderr, "Generated: %lld, Speed: %s\n", current, rate_str.c_str());
    }
}

static void print_help(const char* progname) {
    fprintf(stderr,
        "Usage: %s [options]\n\n"
        "Options:\n"
        "  -t <threads>          : number of threads\n"
        "  -f <file>             : file with known addresses for collision check\n"
        "  -o <outfile>          : output file for results (default: out.list)\n"
        "  -u <interval>         : update interval for speed report in seconds (default: 1)\n"
        "  --test                : run in test mode (generate a few keys and exit)\n"
        "  --disable-p2pkh       : do not generate/check p2pkh addresses (start with '1')\n"
        "  --disable-p2wpkh-p2sh : do not generate/check p2wpkh-p2sh addresses (start with '3')\n"
        "  --disable-p2wpkh      : do not generate/check p2wpkh (bc1) addresses\n"
        "  -h, --help            : show this help\n"
        "\nExample:\n"
        "  %s -t 4 -f known.txt -o results.list -u 2\n"
        , progname, progname);
}

static void generate_wallets_thread(int thread_id, bool is_legacy, uint64_t base_seed, secp256k1_context *ctx) {
    std::mt19937_64 rng(base_seed);
    uint8_t priv[32];
    while(!test_mode) {
        generate_privkey(rng, priv, ctx);
        std::string p2pkh_wif, p2pkh_addr;
        std::string p2wpkh_p2sh_wif, p2wpkh_p2sh_addr;
        std::string p2wpkh_wif, p2wpkh_addr;
        generate_all_addresses_from_priv(priv, ctx,
                                         p2pkh_wif, p2pkh_addr, 
                                         p2wpkh_p2sh_wif, p2wpkh_p2sh_addr,
                                         p2wpkh_wif, p2wpkh_addr);

        int count_gen = 0;
        if (enable_p2pkh) count_gen++;
        if (enable_p2wpkh_p2sh) count_gen++;
        if (enable_p2wpkh) count_gen++;

        generated_count.fetch_add(count_gen, std::memory_order_relaxed);

        if (have_known) {
            auto check_and_write = [&](const std::string &wif_s, const std::string &addr_s) {
                if (addr_s.empty()) return;
                bool found=false;
                // Check if address found in known sets
                if ((addr_s[0]=='1' || addr_s[0]=='3') && known_addresses_legacy.find(addr_s)!=known_addresses_legacy.end()) found=true;
                else if (addr_s.size()>2 && addr_s[0]=='b' && addr_s[1]=='c' && addr_s[2]=='1' && known_addresses_bc1.find(addr_s)!=known_addresses_bc1.end()) found=true;

                if (found) {
                    std::lock_guard<std::mutex> lock_out(out_file_mutex);
                    out_file << wif_s << " " << addr_s << "\n";
                }
            };

            check_and_write(p2pkh_wif, p2pkh_addr);
            check_and_write(p2wpkh_p2sh_wif, p2wpkh_p2sh_addr);
            check_and_write(p2wpkh_wif, p2wpkh_addr);
        }
    }
}

int main(int argc, char **argv) {
    int N_THREADS = -1; 
    std::string in_file_name = "";
    int update_interval = 1;

    for (int i=1; i<argc; i++) {
        if ((strcmp(argv[i],"-h")==0) || (strcmp(argv[i],"--help")==0)) {
            print_help(argv[0]);
            return 0;
        } else if (strcmp(argv[i],"-t")==0 && i+1<argc) {
            N_THREADS = atoi(argv[++i]);
        } else if (strcmp(argv[i],"-f")==0 && i+1<argc) {
            in_file_name = argv[++i];
        } else if (strcmp(argv[i],"-o")==0 && i+1<argc) {
            out_file_name = argv[++i];
        } else if (strcmp(argv[i],"-u")==0 && i+1<argc) {
            update_interval = atoi(argv[++i]);
        } else if (strcmp(argv[i],"--test")==0) {
            test_mode=true;
        } else if (strcmp(argv[i],"--disable-p2pkh")==0) {
            enable_p2pkh = false;
        } else if (strcmp(argv[i],"--disable-p2wpkh-p2sh")==0) {
            enable_p2wpkh_p2sh = false;
        } else if (strcmp(argv[i],"--disable-p2wpkh")==0) {
            enable_p2wpkh = false;
        }
    }

    if(!test_mode && (N_THREADS<1 || in_file_name.empty())) {
        print_help(argv[0]);
        return 1;
    }

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

    uint64_t global_seed;
    {
        std::ifstream urand("/dev/urandom", std::ios::binary);
        if (urand.is_open()) {
            urand.read((char*)&global_seed, sizeof(global_seed));
        } else {
            std::random_device rd;
            global_seed = ((uint64_t)rd() << 32) ^ (uint64_t)time(NULL);
        }
    }

    if (test_mode) {
        out_file.open(out_file_name.c_str(), std::ios::app);
        if(!out_file.is_open()) {
            fprintf(stderr,"Could not open out file: %s\n", out_file_name.c_str());
            secp256k1_context_destroy(ctx);
            return 1;
        }

        std::mt19937_64 rng(global_seed);

        for(int i=0;i<5;i++) {
            uint8_t priv[32];
            do {
                for (int j=0;j<32;j++) priv[j]=(uint8_t)(rng() & 0xFF);
            } while(!secp256k1_ec_seckey_verify(ctx, priv));

            std::string p2pkh_wif, p2pkh_addr;
            std::string p2wpkh_p2sh_wif, p2wpkh_p2sh_addr;
            std::string p2wpkh_wif, p2wpkh_addr;
            generate_all_addresses_from_priv(priv, ctx, 
                                             p2pkh_wif, p2pkh_addr, 
                                             p2wpkh_p2sh_wif, p2wpkh_p2sh_addr,
                                             p2wpkh_wif, p2wpkh_addr);
            if (!p2pkh_addr.empty())      out_file << p2pkh_wif << " " << p2pkh_addr << "\n";
            if (!p2wpkh_p2sh_addr.empty())out_file << p2wpkh_p2sh_wif << " " << p2wpkh_p2sh_addr << "\n";
            if (!p2wpkh_addr.empty())     out_file << p2wpkh_wif << " " << p2wpkh_addr << "\n";
        }
        out_file.close();
        secp256k1_context_destroy(ctx);
        return 0;
    }

    {
        std::ifstream fin(in_file_name);
        if(!fin.is_open()) {
            fprintf(stderr,"Could not open file: %s\n", in_file_name.c_str());
            secp256k1_context_destroy(ctx);
            return 1;
        }
        std::string line;
        int total_1=0;   // P2PKH (start with '1')
        int total_3=0;   // P2SH (start with '3')
        int total_bc1=0; // Bech32 (start with 'bc1')

        while(std::getline(fin,line)) {
            if (!line.empty()) {
                if (line[0]=='1') {
                    known_addresses_legacy.insert(line);
                    total_1++;
                } else if (line[0]=='3') {
                    known_addresses_legacy.insert(line);
                    total_3++;
                } else if (line.size()>2 && line[0]=='b' && line[1]=='c' && line[2]=='1') {
                    known_addresses_bc1.insert(line);
                    total_bc1++;
                }
            }
        }
        fin.close();

        int total_legacy = total_1 + total_3;

        if (!known_addresses_legacy.empty() || !known_addresses_bc1.empty()) {
            have_known = true;
            fprintf(stderr, "Loaded known addresses:\n");
            fprintf(stderr, "  Legacy (P2PKH, '1'): %d\n", total_1);
            fprintf(stderr, "  Legacy (P2SH, '3'): %d\n", total_3);
            fprintf(stderr, "  bc1 (Bech32): %d\n", total_bc1);
            fprintf(stderr, "  Total Legacy (1/3): %d\n", total_legacy);
            fprintf(stderr, "  Total: %d\n", total_legacy+total_bc1);
        } else {
            fprintf(stderr, "No known addresses loaded.\n");
        }
    }

    out_file.open(out_file_name.c_str(), std::ios::app);
    if(!out_file.is_open()) {
        fprintf(stderr,"Could not open out file: %s\n", out_file_name.c_str());
        secp256k1_context_destroy(ctx);
        return 1;
    }

    int half = N_THREADS/2;
    int rest = N_THREADS - half;

    std::vector<std::thread> threads;
    std::thread reporter(speed_reporter_thread, update_interval);

    for (int t=0; t<half; t++) {
        uint64_t seed_for_thread = global_seed + (uint64_t)t*1000000ULL;
        threads.emplace_back(generate_wallets_thread, t, true, seed_for_thread, ctx);
    }
    for (int t=0; t<rest; t++) {
        uint64_t seed_for_thread = global_seed + 100000000ULL + (uint64_t)t*1000000ULL;
        threads.emplace_back(generate_wallets_thread, t, false, seed_for_thread, ctx);
    }

    for (auto &th: threads) th.join();

    out_file.close();
    secp256k1_context_destroy(ctx);

    return 0;
}
