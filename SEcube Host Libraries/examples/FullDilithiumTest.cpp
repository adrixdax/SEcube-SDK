#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#include <sstream>
#include <array>
#include <random>
#include <stdexcept>
#include <thread>  // AGGIUNTO per i timeout
#include <chrono>  // AGGIUNTO per la gestione del tempo
#include "L1.h"

// =============================================================================
// FUNZIONI DI UTILITA'
// =============================================================================

// Stampa banner per pulizia output
void print_banner(const std::string& title) {
    std::cout << "\n================================================================================" << std::endl;
    std::cout << "  " << title << std::endl;
    std::cout << "================================================================================\n" << std::endl;
}

// Converte vettore di byte in stringa esadecimale
std::string to_hex_snippet(const std::vector<uint8_t>& data, size_t max_print = 32) {
    std::stringstream ss;
    size_t print_len = (data.size() < max_print) ? data.size() : max_print;

    for (size_t i = 0; i < print_len; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    }
    if (data.size() > max_print) {
        ss << "... [" << std::dec << data.size() << " bytes totali]";
    }
    return ss.str();
}

// Funzione di "Raffreddamento" per far riposare l'hardware USB
void hsm_cooldown(int milliseconds = 1000) {
    std::cout << "[Zzz] Attesa di " << milliseconds << " ms per stabilizzare l'HSM..." << std::flush;
    std::this_thread::sleep_for(std::chrono::milliseconds(milliseconds));
    std::cout << " Fatto!" << std::endl;
}

// =============================================================================
// TEST COMPLETO: FIRMA, VERIFICA E TAMPERING
// =============================================================================

void run_mldsa_tamper_test(L1& dev, uint16_t level, const std::string& custom_message) {
    print_banner("FASE 1: GENERAZIONE CHIAVI (KEYGEN)");

    std::vector<uint8_t> pk, sk;
    std::cout << "[*] Generazione nuova coppia di chiavi ML-DSA Livello " << level << " sull'HSM..." << std::endl;

    try {
        dev.L1_ML_DSA_Keygen(level, pk, sk);
        std::cout << "[+] KeyGen completata con successo!" << std::endl;
        std::cout << "    -> PK Size : " << pk.size() << " bytes" << std::endl;
        std::cout << "    -> SK Size : " << sk.size() << " bytes" << std::endl;
    } catch (const std::exception& e) {
        std::cout << "[!] Errore durante la KeyGen: " << e.what() << std::endl;
        return;
    }

    hsm_cooldown(1000); // <-- PAUSA POST KEYGEN

    print_banner("FASE 2: FIRMA DEL MESSAGGIO (SIGN)");

    std::cout << "[*] Messaggio in chiaro : \"" << custom_message << "\"" << std::endl;

    std::vector<uint8_t> msg_vec(custom_message.begin(), custom_message.end());
    std::vector<uint8_t> sig;
    std::vector<uint8_t> empty_context;

    std::cout << "[*] Richiesta firma all'HSM (Chunking in azione)..." << std::endl;

    try {
        dev.L1_ML_DSA_Sign(level, sk, msg_vec, sig, empty_context);
        std::cout << "[+] Firma generata con successo!" << std::endl;
        std::cout << "    -> Dimensione Firma: " << sig.size() << " bytes" << std::endl;
        std::cout << "    -> Anteprima Firma : " << to_hex_snippet(sig) << std::endl;
    } catch (const std::exception& e) {
        std::cout << "[!] Errore durante la Firma: " << e.what() << std::endl;
        return;
    }

    hsm_cooldown(1000); // <-- PAUSA POST SIGN

    print_banner("FASE 3: VERIFICA DELLA FIRMA VALIDA (VERIFY)");

    std::cout << "[*] Invio PK, Messaggio e Firma all'HSM per la validazione..." << std::endl;

    try {
        bool is_valid = dev.L1_ML_DSA_Verify(level, pk, msg_vec, sig, empty_context);

        if (is_valid) {
            std::cout << "[+] ESITO: MATCH OK ✅ (La firma originale e' risultata VALIDA)" << std::endl;
        } else {
            std::cout << "[-] ESITO: FAIL ❌ (L'HSM ha respinto la firma originale! Errore di logica?)" << std::endl;
        }
    } catch (const std::exception& e) {
        std::cout << "[-] ESITO: FAIL ❌ (Eccezione catturata: " << e.what() << ")" << std::endl;
    }

    hsm_cooldown(1000); // <-- PAUSA POST VERIFY 1

    print_banner("FASE 4: TAMPERING (MANOMISSIONE DELLA FIRMA)");

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<size_t> dist_index(0, sig.size() - 1);

    size_t tamper_idx = dist_index(gen);
    uint8_t original_byte = sig[tamper_idx];

    uint8_t tampered_byte = original_byte ^ 0xFF;
    sig[tamper_idx] = tampered_byte;

    std::cout << "[*] Attacco in corso: Modifica di un byte casuale nella firma generata..." << std::endl;
    std::cout << "    -> Indice modificato : " << tamper_idx << " (su " << sig.size() << ")" << std::endl;
    std::cout << "    -> Valore originale  : 0x" << std::hex << std::setw(2) << std::setfill('0') << (int)original_byte << std::endl;
    std::cout << "    -> Valore manomesso  : 0x" << std::hex << std::setw(2) << std::setfill('0') << (int)tampered_byte << std::dec << std::endl;

    hsm_cooldown(500); // <-- BREVE PAUSA PRE-VERIFY 2

    print_banner("FASE 5: VERIFICA DELLA FIRMA MANOMESSA (VERIFY)");

    std::cout << "[*] Invio PK, Messaggio e FIRMA CORROTTA all'HSM per la validazione..." << std::endl;

    try {
        bool is_valid = dev.L1_ML_DSA_Verify(level, pk, msg_vec, sig, empty_context);

        if (is_valid) {
            std::cout << "[!!!] ESITO: ALLARME ROSSO 🚨 (La firma MANOMESSA e' risultata valida!)" << std::endl;
        } else {
            std::cout << "[+] ESITO: MATCH RIGETTATO CORRETTAMENTE ✅" << std::endl;
            std::cout << "    L'HSM ha rilevato la corruzione e ha respinto la firma." << std::endl;
        }
    } catch (const std::exception& e) {
        std::cout << "[+] ESITO: MATCH RIGETTATO CORRETTAMENTE ✅" << std::endl;
        std::cout << "    L'HSM (o il driver Host) ha sollevato un'eccezione per firma non valida." << std::endl;
        std::cout << "    -> Dettaglio: " << e.what() << std::endl;
    }
}

// =============================================================================
// MAIN ENTRY POINT
// =============================================================================

int main() {
    print_banner("INIZIALIZZAZIONE DISPOSITIVO SECUBE");
    L1 dev;

    std::array<uint8_t, 32> pin = {0};
    pin[0] = 't'; pin[1] = 'e'; pin[2] = 's'; pin[3] = 't';

    try {
        std::cout << "[*] Esecuzione L1Login..." << std::endl;
        dev.L1Login(pin, SE3_ACCESS_USER, true);
        std::cout << "[+] Login completato con successo." << std::endl;
    } catch (const std::exception& e) {
        std::cout << "[!!!] ERRORE DURANTE IL LOGIN: " << e.what() << std::endl;
        return -1;
    }

    hsm_cooldown(500); // <-- PAUSA POST LOGIN

    std::string test_message = "Hello World!";

    // Eseguiamo il test (Livello 2 = ML-DSA-44)
    run_mldsa_tamper_test(dev, 2, test_message);
    
    try {
        std::cout << "\n[*] Esecuzione L1Logout..." << std::endl;
        dev.L1Logout();
        std::cout << "[+] Logout completato." << std::endl;
    } catch (...) {
        std::cout << "[!] Errore durante il logout." << std::endl;
    }

    return 0;
}