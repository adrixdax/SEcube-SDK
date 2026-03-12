/**
  ******************************************************************************
  * File Name          : digest_algorithms.cpp
  * Description        : Usage example of L1 digest APIs including XOFs.
  ******************************************************************************
  */

#include "../sources/L1/L1.h"
#include <thread>
#include <iostream>
#include <cstring>

using namespace std;

int digest_example() {
    char digest_input[] = "Hello World!";
    int testsize = strlen(digest_input);

    unique_ptr<L0> l0 = make_unique<L0>();
    unique_ptr<L1> l1 = make_unique<L1>();

    cout << "Welcome to SEcube digest example!" << endl;
    this_thread::sleep_for(chrono::milliseconds(1000));
    cout << "Looking for SEcube devices...\n" << endl;
    this_thread::sleep_for(chrono::milliseconds(1000));

    int numdevices = l0->GetNumberDevices();
    if(numdevices == 0){
        cout << "No SEcube devices found! Quit." << endl;
        return 0;
    }

    vector<pair<string, string>> devices;
    int ret = l0->GetDeviceList(devices);
    if(ret){
        cout << "Error while searching for SEcube devices! Quit." << endl;
        return -1;
    }

    cout << "Number of SEcube devices found: " << numdevices << endl;
    cout << "List of SEcube devices (path, serial number):" << endl;
    int index = 0;
    uint8_t empty_serial_number[L0Communication::Size::SERIAL];
    memset(empty_serial_number, 0, L0Communication::Size::SERIAL);

    for(pair<string, string> p : devices){
        if(p.second.empty() || memcmp(p.second.data(), empty_serial_number, L0Communication::Size::SERIAL)==0){
            cout << index << ") " << p.first << " - serial number not available (please initialize this SEcube)" << endl;
        } else {
            cout << index << ") " << p.first << " - " << p.second << endl;
        }
        index++;
    }

    int sel = 0;
    cout << "\nEnter the number corresponding to the SEcube device that you want to use..." << endl;
    if(!(cin >> sel)){
        cout << "Input error...quit." << endl;
        return -1;
    }

    vector<pair<uint32_t, uint16_t>> keys;
    int cnt = 0, ch = 0;

    if((sel >= 0) && (sel < numdevices)){
        array<uint8_t, L0Communication::Size::SERIAL> sn = {0};
        if(devices.at(sel).second.length() > L0Communication::Size::SERIAL){
            cout << "Unexpected error...quit." << endl;
            return -1;
        } else {
            memcpy(sn.data(), devices.at(sel).second.data(), devices.at(sel).second.length());
        }

        l1->L1SelectSEcube(sn);
        cout << "\nDevice " << devices.at(sel).first << " - " << devices.at(sel).second << " selected." << endl;

        array<uint8_t, 32> pin = {'t','e','s','t'};
        l1->L1Login(pin, SE3_ACCESS_USER, true);

        cout << "\n\nThe SEcube SDK currently supports the following algorithms:" << endl;
        vector<se3Algo> algos;
        try{
            l1->L1GetAlgorithms(algos);
        } catch (...) {
            cout << "Unexpected error...quit." << endl;
            l1->L1Logout();
            return -1;
        }
        for(se3Algo algo : algos){
            algo.print();
        }

        cout << "\nWe are going to compute the digest of the following string:" << endl;
        cout << digest_input << endl;
        shared_ptr<uint8_t[]> input_data(new uint8_t[testsize]);
        memcpy(input_data.get(), digest_input, testsize);

        sel = 0;
        cout << "\nPlease enter the number associated to the algorithm for the digest computation:" << endl;
        cout << "0) SHA-256" << endl;
        cout << "1) HMAC-SHA-256" << endl;
        cout << "2) SHA3-224" << endl;
        cout << "3) SHA3-256" << endl;
        cout << "4) SHA3-384" << endl;
        cout << "5) SHA3-512" << endl;
        cout << "6) SHAKE128 (XOF)" << endl;
        cout << "7) SHAKE256 (XOF)" << endl;

        if(!(cin >> sel)){
            cout << "Input error...quit." << endl;
            l1->L1Logout();
            return -1;
        }

        SEcube_digest data_digest;
        SEcube_digest temp;
        size_t shake_len = 0;

        // Se l'utente seleziona una XOF, chiediamo la lunghezza desiderata
        if (sel == 6 || sel == 7) {
            cout << "\n[XOF] Quanti byte vuoi estrarre per questa funzione SHAKE? ";
            if(!(cin >> shake_len) || shake_len <= 0) {
                cout << "Lunghezza non valida...quit." << endl;
                l1->L1Logout();
                return -1;
            }
            data_digest.shake_requested_len = shake_len; // Impostiamo la lunghezza dinamica
        }

        cout << "\nStarting digest computation..." << endl;

        switch(sel){
            case 0:
                data_digest.algorithm = L1Algorithms::Algorithms::SHA256;
                l1->L1Digest(testsize, input_data, data_digest);
                break;
            case 1:
                cout << "\nThese are the keys stored on the SEcube." << endl;
                // ... (Logica HMAC intatta) ...
                try{ l1->L1KeyList(keys); }
                catch (...) { cout << "Error. Quit." << endl; l1->L1Logout(); return -1; }
                if(keys.size() == 0){ cout << "No keys. Quit." << endl; l1->L1Logout(); return -1; }
                for(pair<uint32_t, uint16_t> k : keys){
                    cout << cnt << ") Key ID " << k.first << " - length: " << 8*k.second << " bit" << endl;
                    cnt++;
                }
                if(!(cin >> ch)){ cout << "Input error...quit." << endl; l1->L1Logout(); return -1; }

                data_digest.key_id = keys.at(ch).first;
                data_digest.usenonce = false;
                data_digest.algorithm = L1Algorithms::Algorithms::HMACSHA256;
                l1->L1Digest(testsize, input_data, data_digest);
                break;
            case 2:
                data_digest.algorithm = L1Algorithms::Algorithms::SHA3_224;
                l1->L1Digest(testsize, input_data, data_digest);
                break;
            case 3:
                data_digest.algorithm = L1Algorithms::Algorithms::SHA3_256;
                l1->L1Digest(testsize, input_data, data_digest);
                break;
            case 4:
                data_digest.algorithm = L1Algorithms::Algorithms::SHA3_384;
                l1->L1Digest(testsize, input_data, data_digest);
                break;
            case 5:
                data_digest.algorithm = L1Algorithms::Algorithms::SHA3_512;
                l1->L1Digest(testsize, input_data, data_digest);
                break;
            case 6:
                data_digest.algorithm = L1Algorithms::Algorithms::SHAKE_128; // Assicurati che sia 8 nell'enum
                l1->L1Digest(testsize, input_data, data_digest);
                break;
            case 7:
                data_digest.algorithm = L1Algorithms::Algorithms::SHAKE_256; // Assicurati che sia 9 nell'enum
                l1->L1Digest(testsize, input_data, data_digest);
                break;
            default:
                cout << "Input error...quit." << endl;
                l1->L1Logout();
                return -1;
        }

        cout << "\nPlaintext: " << digest_input << endl;
        this_thread::sleep_for(chrono::milliseconds(1000));

        cout << "\n\nThe hex value of the digest is (" << data_digest.get_digest_len() << " bytes):" << endl;
        for (unsigned int i = 0 ; i < data_digest.get_digest_len(); i++) {
            // Usa std::vector per l'indicizzazione
            printf("%02x ", data_digest.digest[i]);
        }

        if(data_digest.algorithm == L1Algorithms::Algorithms::HMACSHA256){
            cout << "\n\nThe hex value of the recomputed digest is:" << endl;
            for(unsigned int i = 0; i < temp.get_digest_len(); i++){
                printf("%02x ", temp.digest[i]);
            }
            if(temp.digest == data_digest.digest){
                cout << "\nOriginal digest and recomputed digest are equal. OK." << endl;
            } else {
                cout << "\nOriginal digest and recomputed digest are not equal. Something went wrong..." << endl;
            }
        }

        l1->L1Logout();
        cout << "\n\nExample completed. Press 'q' to quit." << endl;
        while(cin.get() != 'q'){};
    } else {
        cout << "You entered an invalid number. Quit." << endl;
        return 0;
    }
    return 0;
}