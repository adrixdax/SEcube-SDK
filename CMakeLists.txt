cmake_minimum_required(VERSION 4.1)
project(SEcube_SDK)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_C_STANDARD 99)

# --- PERCORSI ---
set(FIRMWARE_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/SEcube USBStick Firmware/Project")
set(FIRMWARE_C_DIR "${FIRMWARE_ROOT}/Src/Device")
set(FIRMWARE_INC_DIR "${FIRMWARE_ROOT}/Inc")
set(HOST_LIB_DIR "${CMAKE_CURRENT_SOURCE_DIR}/SEcube Host Libraries/sources")
set(OPENSSL_DIR "${CMAKE_CURRENT_SOURCE_DIR}/openssl-master")
set(ML_DSA_OPENSSL "${OPENSSL_DIR}/crypto/ml_dsa"
)



# --- INCLUDE ---
include_directories(
        "${FIRMWARE_INC_DIR}/Device"
        "${FIRMWARE_INC_DIR}/Common"
        "${FIRMWARE_INC_DIR}"
        "${HOST_LIB_DIR}"
        "${HOST_LIB_DIR}/L0"
        "${HOST_LIB_DIR}/L0/L0 Base"
        "${HOST_LIB_DIR}/L1"
        "${HOST_LIB_DIR}/L1/L1 Base"
        "${OPENSSL_DIR}/include"
)

# --- SORGENTI ---
add_executable(SEcube_SDK
        # 1. LOGICA FIRMWARE (HSM) - TUTTI i file necessari per la matematica
        "${FIRMWARE_C_DIR}/se3_algo_mldsa.c"
        "${FIRMWARE_C_DIR}/se3_arith_ntt.c"
        "${FIRMWARE_C_DIR}/se3_arith_polyvec.c"
        "${FIRMWARE_C_DIR}/se3_arith_packing.c"
        "${FIRMWARE_C_DIR}/se3_arith_poly.c"      # <--- AGGIUNTO: Risolve polyeta_unpack, ecc.
        "${FIRMWARE_ROOT}/Src/Common/Keccak.c"    # UNICO Keccak
        "${FIRMWARE_ROOT}/Src/Common/shake.c"     # UNICO Shake
        # 2. OpenSSL CrossReference
        "${ML_DSA_OPENSSL}/ml_dsa_key.c"

        # 4. TEST
        "SEcube Host Libraries/examples/hostSideTest.cpp"
)

# --- DEFINIZIONI ---
target_compile_definitions(SEcube_SDK PRIVATE
        USE_CCRAM_SECTION
        SIMULAZIONE_PC
)

find_package(OpenSSL REQUIRED)

target_link_libraries(SEcube_SDK PRIVATE OpenSSL::Crypto)