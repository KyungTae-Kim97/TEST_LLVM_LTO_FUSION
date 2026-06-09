cmake_minimum_required(VERSION 3.16)
project(ZeroCacheMissBenchmark) 

set(CMAKE_CXX_STANDARD 17)

# 1. 컴파일러를 반드시 Clang으로 강제 지정 (LLVM Pass 호환)
set(CMAKE_CXX_COMPILER "clang++")
set(CMAKE_C_COMPILER "clang")

find_package(fastrtps REQUIRED)
find_package(fastcdr REQUIRED)

# 2. 랩탑에서 가져온 LTO Pass 및 암호화 오브젝트 파일 경로 지정
set(PASS_PLUGIN_PATH "${CMAKE_CURRENT_SOURCE_DIR}/libCryptoFusionPass.so")
set(CRYPTO_LIB_PATH "${CMAKE_CURRENT_SOURCE_DIR}/libFusedCryptoPayload.so")

# 3. C++ 컴파일 및 링커 플래그 설정
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -flto -fpass-plugin=${PASS_PLUGIN_PATH} -march=armv8.2-a+crypto")

# 🚨 [수정됨] -rdynamic 유지 + LTO 심볼 삭제 방지(-Wl,-u) 추가
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -rdynamic -flto -fpass-plugin=${PASS_PLUGIN_PATH} -march=armv8.2-a+crypto -Wl,-u,fuse_init -Wl,-u,fuse_update_enc -Wl,-u,fuse_finalize_enc -Wl,-u,g_fuse_active")

add_executable(Benchmark 
    main.cpp 
    VariablePayload.cxx 
    VariablePayloadPubSubTypes.cxx
)

# 🚨 [수정됨] 라이브러리 강제 링크 (--no-as-needed)
target_link_libraries(Benchmark 
    fastrtps 
    fastcdr 
    -Wl,--no-as-needed "${CRYPTO_LIB_PATH}" -Wl,--as-needed
    crypto 
)