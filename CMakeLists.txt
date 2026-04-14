cmake_minimum_required(VERSION 4.1)
project(SEcube_SDK)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_C_STANDARD 99)

# --- PERCORSI ---
set(HOST_LIB_DIR "${CMAKE_CURRENT_SOURCE_DIR}/SEcube Host Libraries/sources")

# --- INCLUDE ---
include_directories(
        "${HOST_LIB_DIR}"
        "${HOST_LIB_DIR}/L0"
        "${HOST_LIB_DIR}/L0/L0 Base"
        "${HOST_LIB_DIR}/L0/L0 Support"    # <--- AGGIUNTO per AES/HMAC
        "${HOST_LIB_DIR}/L1"
        "${HOST_LIB_DIR}/L1/L1 Base"
        "${HOST_LIB_DIR}/L1/Crypto Libraries" # <--- AGGIUNTO per Keccak
)

# --- SORGENTI ---
add_executable(SEcube_SDK
        # 2. HOST LIBRARIES - LIVELLO L0 (Hardware)
        "${HOST_LIB_DIR}/L0/L0.cpp"
        "${HOST_LIB_DIR}/L0/L0 Base/L0_base.cpp"
        "${HOST_LIB_DIR}/L0/L0_commodities.cpp"
        "${HOST_LIB_DIR}/L0/L0_communication.cpp"
        "${HOST_LIB_DIR}/L0/L0_provision.cpp"        # <--- RISOLVE L0FactoryInit

        # 3. HOST LIBRARIES - LIVELLO L1 (Protocollo & ML-DSA Wrapper)
        "${HOST_LIB_DIR}/L1/L1.cpp"
        "${HOST_LIB_DIR}/L1/L1 Base/L1_base.cpp"
        "${HOST_LIB_DIR}/L1/L1_login_logout.cpp"
        "${HOST_LIB_DIR}/L1/L1_security.cpp"         # <--- RISOLVE CryptoInit, Encrypt, Decrypt
        "${HOST_LIB_DIR}/L1/L1_sekey.cpp"            # <--- RISOLVE KeyList, Sign, Verify, Keygen

        # 4. CRITTOGRAFIA HOST (Supporto al Login/Sessione)
        "${HOST_LIB_DIR}/L1/Crypto Libraries/shake.c"
        "${HOST_LIB_DIR}/L1/Crypto Libraries/Keccak.c"
        "${HOST_LIB_DIR}/L1/Crypto Libraries/sha256.c"
        "${HOST_LIB_DIR}/L1/Crypto Libraries/aes256.cpp"
        "${HOST_LIB_DIR}/L1/Crypto Libraries/pbkdf2.c"

        # 5. ENTRY POINT (Il test che stai compilando)
        "SEcube Host Libraries/examples/dilithium_call.cpp"
        #"SEcube Host Libraries/examples/FullDilithiumTest.cpp"
)

