#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#include <sstream>
#include <chrono>
#include <thread>
#include <numeric>
#include <cmath>
#include <algorithm>
#include "L1.h"

// =============================================================================
// DATI DI RIFERIMENTO OPENSSL (SOLO LIVELLO 2)
// =============================================================================
const std::string OPENSSL_PUB_RAW = R"(
    ba:71:f9:f6:4e:11:ba:eb:58:fa:9c:6f:bb:6e:14:
    e6:1f:18:64:3d:ab:49:5b:47:53:9a:91:66:ca:01:
    98:13:1c:44:f8:26:bb:d5:6e:34:e5:5d:b5:e5:e2:
    d7:33:48:5e:39:ea:26:0f:c6:00:0c:5e:a4:ba:80:
    d3:45:5c:de:53:b4:6f:34:48:2a:ed:fd:54:50:fc:
    2e:1b:a4:f2:5d:15:f9:c1:44:24:2f:b3:9b:b5:22:
    87:18:90:30:c5:04:98:e1:71:7b:7c:75:8b:19:0a:
    67:48:ea:9a:a3:f7:ac:aa:f2:c7:cb:52:6e:d7:17:
    c9:f7:9a:eb:84:21:4f:a5:cd:8d:ed:92:a0:c3:fa:
    15:58:81:0f:12:c7:05:0a:36:77:08:d1:96:cd:24:
    e5:af:97:49:04:ae:d8:e4:ce:88:72:e8:69:6b:0b:
    7b:ca:50:e4:52:cd:7d:30:ea:9a:4a:da:c0:31:1d:
    67:2c:6b:de:84:96:24:0b:07:43:14:63:70:88:95:
    cd:9b:af:c3:16:32:d7:39:76:49:38:8f:da:fc:bf:
    7d:30:5a:3d:e9:a4:95:ec:a7:43:3a:8f:83:ba:0f:
    0b:25:c4:13:c6:e3:9c:96:eb:7d:69:1b:34:d3:7c:
    e3:7f:1e:ea:d1:cf:21:7e:25:ef:34:ee:cf:3f:7c:
    60:f8:4b:8e:df:dd:e8:40:5d:4f:83:25:76:c6:1e:
    f9:8e:0a:2f:28:da:18:77:00:95:39:24:f6:86:b9:
    46:14:70:5b:cf:53:d3:3f:ed:d4:34:8e:dd:db:df:
    28:b5:06:5e:1f:20:77:50:43:e8:5c:f9:31:f8:29:
    17:93:63:a1:a7:e7:40:4a:83:8e:c0:00:86:b0:97:
    63:86:fe:63:7c:98:24:47:57:e3:f7:69:dd:d4:46:
    74:71:bf:ad:67:0f:9a:05:f8:24:6e:e5:0a:7b:1e:
    af:87:fc:40:69:c3:ae:2a:a2:03:32:58:11:77:92:
    f0:bc:d4:9e:08:3f:d1:bc:74:96:ab:ff:29:cc:94:
    e4:86:8b:21:21:4e:d3:16:52:53:99:a6:10:fb:dd:
    4a:80:e7:c8:07:15:f2:95:78:e2:a8:4b:b4:0b:dd:
    db:d9:f4:7a:11:b6:e7:da:11:8a:1b:65:8d:35:9e:
    8a:ef:55:eb:46:b5:37:6b:5b:65:59:79:98:4a:92:
    2b:ee:bf:c5:9b:cd:60:0d:53:09:dc:cd:72:db:f0:
    78:7d:b8:ba:75:7b:53:7c:1e:af:d5:c0:f5:0e:a4:
    bc:95:83:54:9e:28:29:a4:2c:28:ca:c2:48:c9:6d:
    78:12:4c:47:15:9b:18:ae:dd:75:4a:ba:17:b1:9d:
    43:0f:b7:8f:63:3e:a9:d2:6f:54:a9:bd:50:f8:d8:
    f6:b7:35:94:f8:28:97:6e:7e:a0:9c:53:bb:b9:f1:
    1a:56:c9:50:7f:b8:9b:9a:5e:bc:03:7a:37:26:7a:
    95:f8:5b:8d:64:ca:97:19:2b:10:a6:6f:41:7b:3f:
    61:fe:9c:a5:71:30:a4:8f:d9:25:ea:e2:ab:55:02:
    d5:71:c8:a5:19:03:c1:d3:98:f4:c1:f7:6a:7e:11:
    74:39:76:af:db:c6:97:f2:30:94:a3:cd:76:1f:f9:
    68:5d:e3:2e:09:fb:3c:28:ad:d4:53:49:03:00:bc:
    7c:89:dc:01:78:00:96:07:17:22:94:57:75:f2:64:
    e1:b0:62:3b:cf:46:19:c7:12:c8:38:76:12:05:d8:
    76:91:b7:5e:f3:60:19:6c:bb:9e:9b:92:a0:d4:c4:
    ed:62:32:6e:50:24:d7:75:10:b8:ee:2c:74:26:cc:
    22:ea:e2:09:dc:9f:13:bd:e6:bf:08:f5:e7:18:1b:
    d3:b4:59:45:0b:45:1a:51:53:9a:71:5c:21:d6:7d:
    d3:30:eb:59:70:db:00:d9:ed:bf:b2:82:2b:03:6f:
    a1:3b:af:eb:86:d8:dc:78:86:6e:3f:8d:43:e5:3d:
    78:cc:a5:59:5a:6f:af:88:6b:5d:c1:12:f1:cf:4a:
    dc:fa:87:58:00:d9:0b:48:88:3a:f9:73:16:fe:15:
    06:87:3f:c1:57:e5:70:ea:cb:fd:22:28:68:d1:42:
    34:10:19:66:af:b6:bf:99:40:82:92:53:a9:53:ad:
    a8:9f:c7:56:b6:a8:49:f7:0a:cb:98:38:e6:9f:aa:
    50:bb:a7:5e:3e:89:c2:ad:b5:7e:86:d0:88:ab:9b:
    04:a2:8e:67:07:09:17:22:43:ec:5e:00:08:a5:ce:
    af:3f:87:22:f4:87:30:25:96:ff:d7:55:ad:1b:82:
    a4:9c:34:b3:46:95:15:b4:6a:a2:90:cd:86:ee:38:
    ea:7a:9b:e3:f1:03:61:03:35:b5:31:cc:a3:33:dd:
    fe:32:b1:45:10:f4:b0:7e:f9:5f:c6:68:4e:8c:45:
    4a:92:c1:0d:bb:5d:59:c7:a7:c6:3f:b3:05:fe:88:
    19:67:d9:9e:66:9e:b6:32:84:05:82:56:0b:b4:03:
    43:1d:40:f7:5a:49:54:90:84:82:27:82:92:82:1f:
    4e:a9:1e:42:e7:8f:a4:8c:ae:e3:c8:36:14:6d:cf:
    d7:38:d1:17:e9:2e:9a:15:13:7d:28:e8:e6:a4:b4:
    62:26:50:cb:41:35:04:cb:3a:33:5d:44:be:ec:57:
    46:c1:c2:94:b1:e8:cb:99:cb:60:8d:92:8f:8c:e3:
    56:36:32:c5:21:f2:3d:13:c6:1a:8f:61:c0:1d:f8:
    c9:6c:73:60:db:4f:3c:68:aa:5d:2f:dd:34:2a:62:
    ff:34:59:c1:16:38:94:21:ab:43:e8:58:4c:45:88:
    2b:50:e6:e4:e9:6d:b6:f0:b8:fd:e8:90:d5:db:fa:
    dc:d8:86:90:b4:49:e6:42:40:dd:b2:02:37:47:f3:
    08:36:3e:30:1a:a7:77:57:16:9f:c6:15:06:28:d5:
    92:0b:5a:a1:ab:1c:8c:bf:44:cb:00:e0:25:d7:87:
    9d:72:b4:79:e3:af:53:11:c7:85:72:55:90:da:9c:
    89:b9:fc:3b:84:50:76:95:54:eb:44:d2:03:eb:a2:
    bb:ae:f9:ca:d2:23:70:11:c2:ea:44:ef:f0:0f:29:
    9a:48:ff:e2:8c:a9:3d:df:85:f7:66:08:24:2e:f8:
    d6:cc:24:61:0a:1e:20:78:fc:ac:4f:93:85:c3:14:
    90:5e:ca:a8:2e:55:39:16:d9:4d:1a:7c:1e:c6:52:
    aa:08:89:70:83:da:a2:eb:b1:77:5f:bc:47:1a:e2:
    77:77:d7:90:4e:a9:f1:b9:2b:ca:c3:d8:a3:15:84:
    26:08:7b:64:5b:11:08:f0:d6:5f:ec:93:78:9c:05:
    37:43:ca:14:fd:63:d0:5e:98:b6:52:df:2b:9c:2f:
    f9:ce:05:f1:94:07:03:ff:b2:73:f8:0e:0e:27:32:
    ec:a9:96:0d:98:1b:4c:fd:3b:7b:b8:04:5b:3c:38:
    30:54:6b:9d:d8:db:0d
)";

// =============================================================================
// UTILITY STATISTICHE
// =============================================================================

struct Stats {
    std::vector<double> samples;

    double average() const {
        return std::accumulate(samples.begin(), samples.end(), 0.0) / samples.size();
    }

    double std_dev() const {
        double avg = average();
        double sum = 0;
        for(double s : samples) sum += (s - avg) * (s - avg);
        return std::sqrt(sum / samples.size());
    }

    double min() const { return *std::min_element(samples.begin(), samples.end()); }
    double max() const { return *std::max_element(samples.begin(), samples.end()); }
};

// =============================================================================
// UTILITY DI PULIZIA E CONFRONTO
// =============================================================================

// Rimuove spazi, ":" e "\n" lasciando solo i caratteri hex
std::string clean_hex(const std::string& input) {
    std::string out;
    for (char c : input) {
        if (std::isxdigit(static_cast<unsigned char>(c)))
            out += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return out;
}

// Costante con la Public Key formattata e pronta per il confronto
const std::string EXPECTED_PK_HEX = clean_hex(OPENSSL_PUB_RAW);

std::string bytes_to_hex(const std::vector<uint8_t>& data) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (auto b : data) ss << std::setw(2) << static_cast<int>(b);
    return ss.str();
}

void internal_cooldown(int ms = 500) {
    std::this_thread::sleep_for(std::chrono::milliseconds(ms));
}

// =============================================================================
// TEST ENGINE PER LIVELLO SPECIFICO
// =============================================================================
double run_statistical_test(L1& dev, uint16_t level, int iterations) {
    std::string algo_name = (level == 2 ? "ML-DSA-44" : level == 3 ? "ML-DSA-65" : "ML-DSA-87");
    Stats kg_stats, sign_stats, verify_stats;
    std::vector<uint8_t> pk, sk, sig, ctx;
    std::vector<uint8_t> msg = {'S', 't', 'a', 't', 's', ' ', (uint8_t)('0' + level)};

    std::cout << "\n>>> BENCHMARK LIVELLO " << level << " (" << iterations << " campioni) <<<" << std::endl;

    for (int i = 0; i < iterations; ++i) {
        auto t1 = std::chrono::high_resolution_clock::now();
        dev.L1_ML_DSA_Keygen(level, pk, sk);
        auto t2 = std::chrono::high_resolution_clock::now();
        kg_stats.samples.push_back(std::chrono::duration<double, std::milli>(t2 - t1).count());

        auto t3 = std::chrono::high_resolution_clock::now();
        dev.L1_ML_DSA_Sign(level, msg, sk, sig, ctx);
        auto t4 = std::chrono::high_resolution_clock::now();
        sign_stats.samples.push_back(std::chrono::duration<double, std::milli>(t4 - t3).count());

        auto t5 = std::chrono::high_resolution_clock::now();
        dev.L1_ML_DSA_Verify(level, msg, sig, pk, ctx);
        auto t6 = std::chrono::high_resolution_clock::now();
        verify_stats.samples.push_back(std::chrono::duration<double, std::milli>(t6 - t5).count());

        if ((i + 1) % 10 == 0) std::cout << "." << std::flush;
    }

    // Calcoliamo il tempo netto di calcolo HSM per questo livello
    double net_hsm_lv = std::accumulate(kg_stats.samples.begin(), kg_stats.samples.end(), 0.0) +
                        std::accumulate(sign_stats.samples.begin(), sign_stats.samples.end(), 0.0) +
                        std::accumulate(verify_stats.samples.begin(), verify_stats.samples.end(), 0.0);

    // Output Risultati
    auto print_row = [](std::string label, const Stats& s) {
        printf("\n%-10s | Media: %7.2f ms | Dev.Std: %5.2f ms | Min: %7.2f | Max: %7.2f",
               label.c_str(), s.average(), s.std_dev(), s.min(), s.max());
    };

    std::cout << "\n-----------------------------------------------------------------------";
    print_row("KeyGen", kg_stats);
    print_row("Sign", sign_stats);
    print_row("Verify", verify_stats);
    std::cout << "\n-----------------------------------------------------------------------\n";

    return net_hsm_lv;
}

// =============================================================================
// MAIN
// =============================================================================

int main() {
    std::array<uint8_t, 32> pin = {0};
    pin[0] = 't'; pin[1] = 'e'; pin[2] = 's'; pin[3] = 't';
    L1 dev;
    int X = 1500;
    double hsm_pure_total = 0;
    double total_sleep_time = 0;

    auto start_global = std::chrono::high_resolution_clock::now();

    try {
        dev.L1Login(pin, SE3_ACCESS_USER, true);
        std::vector<uint16_t> levels = {2, 3, 5};

        for (uint16_t lv : levels) {
            // Eseguiamo il test e prendiamo il tempo NETTO dei calcoli
            hsm_pure_total += run_statistical_test(dev, lv, X);

            dev.L1Logout();
            if (lv != levels.back()) {
                std::cout << "[!] Cooldown 1s..." << std::endl;
                std::this_thread::sleep_for(std::chrono::seconds(1));
                total_sleep_time += 1000.0; // Tracciamo lo sleep esplicitamente
                dev.L1Login(pin, SE3_ACCESS_USER, true);
            }
        }

    } catch (const std::exception& e) { std::cerr << "ERRORE: " << e.what() << std::endl; }

    auto end_global = std::chrono::high_resolution_clock::now();
    double wall_clock = std::chrono::duration<double, std::milli>(end_global - start_global).count();

    // Il vero Overhead è tutto ciò che non è calcolo puro e non è sleep programmato
    double hidden_overhead = wall_clock - hsm_pure_total - total_sleep_time;

    std::cout << "\n====================================================" << std::endl;
    std::cout << "ANALISI TEMPORALE DI PRECISIONE (X = " << X << ")" << std::endl;
    std::cout << "----------------------------------------------------" << std::endl;
    printf("1. Tempo Calcolo HSM Puro:    %10.2f ms\n", hsm_pure_total);
    printf("2. Tempo Sleep Programmato:   %10.2f ms\n", total_sleep_time);
    printf("3. Overhead (USB/Logic/I-O):  %10.2f ms\n", hidden_overhead);
    std::cout << "----------------------------------------------------" << std::endl;
    printf("TEMPO TOTALE REALE:           %10.2f ms (%.2f s)\n", wall_clock, wall_clock / 1000.0);
    std::cout << "====================================================" << std::endl;

    return 0;
}