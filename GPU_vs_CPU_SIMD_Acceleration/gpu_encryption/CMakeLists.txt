cmake_minimum_required(VERSION 3.16)
project(MasterFusionPOC LANGUAGES CXX CUDA)

# 🌟 [해결책 1] 최고 수준의 C++ 및 CUDA 최적화 강제 적용
set(CMAKE_BUILD_TYPE Release)
set(CMAKE_CXX_FLAGS "-O3 -march=native")
set(CMAKE_CUDA_FLAGS "-O3 --use_fast_math")
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CUDA_ARCHITECTURES 87) # A100의 경우 80, Jetson Orin Nano는 87

find_package(fastcdr REQUIRED)
find_package(fastrtps REQUIRED) 

# CUDA 커널 정적 라이브러리 컴파일
add_library(crypto_kernel STATIC parallel_gcm.cu)
set_target_properties(crypto_kernel PROPERTIES CUDA_SEPARABLE_COMPILATION ON)

# Publisher 빌드
add_executable(fused_publisher fused_publisher.cpp)
# 🌟 [수정 1] C++ 파일(fused_publisher.cpp) 빌드 시 CUDA 헤더 디렉토리를 포함시킵니다.
target_include_directories(fused_publisher PRIVATE ${CMAKE_CUDA_TOOLKIT_INCLUDE_DIRECTORIES})
target_link_libraries(fused_publisher PRIVATE fastrtps fastcdr crypto_kernel)
# 🌟 [수정 2] 실행 파일 링킹(합치기) 작업을 g++ 대신 nvcc가 수행하도록 강제합니다. (cudart 에러 방지)
set_target_properties(fused_publisher PROPERTIES LINKER_LANGUAGE CUDA)

# Subscriber 빌드
add_executable(fused_subscriber fused_subscriber.cpp)
target_link_libraries(fused_subscriber PRIVATE fastrtps fastcdr)

# Benchmark 빌드
find_package(OpenSSL REQUIRED) # 🌟 OpenSSL 패키지 찾기

add_executable(pipeline_benchmark pipeline_benchmark.cpp)
target_include_directories(pipeline_benchmark PRIVATE ${CMAKE_CUDA_TOOLKIT_INCLUDE_DIRECTORIES} ${OPENSSL_INCLUDE_DIR})
# 🌟 OpenSSL::Crypto 추가
target_link_libraries(pipeline_benchmark PRIVATE crypto_kernel OpenSSL::Crypto) 
set_target_properties(pipeline_benchmark PROPERTIES LINKER_LANGUAGE CUDA)