cmake_minimum_required(VERSION 3.16)
project(MasterFusionPOC LANGUAGES CXX CUDA)

# [Solution 1] Force top-level C++ and CUDA optimizations
set(CMAKE_BUILD_TYPE Release)
set(CMAKE_CXX_FLAGS "-O3 -march=native")
set(CMAKE_CUDA_FLAGS "-O3 --use_fast_math")
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CUDA_ARCHITECTURES 87) # 80 for A100, 87 for Jetson Orin Nano

find_package(fastcdr REQUIRED)
find_package(fastrtps REQUIRED) 

# Compile the CUDA kernel as a static library
add_library(crypto_kernel STATIC parallel_gcm.cu)
set_target_properties(crypto_kernel PROPERTIES CUDA_SEPARABLE_COMPILATION ON)

# Build the Publisher
add_executable(fused_publisher fused_publisher.cpp)
# [Fix 1] Include the CUDA header directory when building the C++ file (fused_publisher.cpp).
target_include_directories(fused_publisher PRIVATE ${CMAKE_CUDA_TOOLKIT_INCLUDE_DIRECTORIES})
target_link_libraries(fused_publisher PRIVATE fastrtps fastcdr crypto_kernel)
# [Fix 2] Force nvcc (instead of g++) to perform the executable linking step. (Prevents cudart errors)
set_target_properties(fused_publisher PROPERTIES LINKER_LANGUAGE CUDA)

# Build the Subscriber
add_executable(fused_subscriber fused_subscriber.cpp)
target_link_libraries(fused_subscriber PRIVATE fastrtps fastcdr)

# Build the Benchmark
find_package(OpenSSL REQUIRED) # Find the OpenSSL package

add_executable(pipeline_benchmark pipeline_benchmark.cpp)
target_include_directories(pipeline_benchmark PRIVATE ${CMAKE_CUDA_TOOLKIT_INCLUDE_DIRECTORIES} ${OPENSSL_INCLUDE_DIR})
# Add OpenSSL::Crypto
target_link_libraries(pipeline_benchmark PRIVATE crypto_kernel OpenSSL::Crypto) 
set_target_properties(pipeline_benchmark PROPERTIES LINKER_LANGUAGE CUDA)