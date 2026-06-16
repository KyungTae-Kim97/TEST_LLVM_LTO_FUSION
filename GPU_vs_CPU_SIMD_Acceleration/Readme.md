# High-Performance SROS2 Cryptography: ARM NEON & GPU Acceleration

![C++](https://img.shields.io/badge/C++-14%2F17-blue.svg)
![LLVM](https://img.shields.io/badge/LLVM-LTO_Pass-red.svg)
![CUDA](https://img.shields.io/badge/CUDA-11.x%2B-green.svg)
![FastDDS](https://img.shields.io/badge/FastDDS-SROS2-green.svg)
![ARM](https://img.shields.io/badge/ARM-NEON_SIMD-orange.svg)

## Overview
This repository presents a dual-architecture approach to eliminating the severe CPU bottlenecks encountered in cryptographic operations for standard SROS2 and FastDDS environments. Traditional cryptographic libraries (e.g., OpenSSL) impose massive latency during payload encryption. To solve this, we introduce two highly optimized, hardware-aware cryptographic engines tailored for different payload scales:

1. CPU SIMD Acceleration: Uses highly scalable ARM NEON SIMD engines for inline encryption (integrated into the middleware via LTO Fusion).
2. GPU Zero-Copy Thunk: Bypasses middleware serialization entirely for massive payloads using Unified Memory and CUDA-accelerated Parallel Tree Reduction.

---

## Architecture I: CPU SIMD Cryptographic Engines
Designed to maximize Instruction-Level Parallelism (ILP) and saturate the CPU vector ALU without triggering register spilling.

The standalone CPU cryptographic payload engines were developed in progressive scaling phases:
* FusedCryptoPayload_1_way_arm.h: The baseline implementation processing 1 AES block (16 bytes) per cycle. Establishes the core mathematical foundation for inline GHASH and AES transformation.
* FusedCryptoPayload_4_way_arm.h: Scales the architecture to process 4 blocks (64 bytes) concurrently using heterogeneous register allocation.
* FusedCryptoPayload_8_way_arm.h: The ultimate execution model processing 8 blocks (128 bytes) in a single loop. Extensively uses 128-bit NEON registers and L1-cache key streaming.

---

## Architecture II: GPU Zero-Copy (Thunk Architecture)
Designed to handle massive data streams where standard network stack copies completely halt the CPU.

* GPU AES-GCM Engine (Parallel Tree Reduction): Overcomes the strict sequential dependency of standard GHASH computation by utilizing a two-pass Parallel Tree Reduction algorithm on the GPU. Uses constant memory for S-Box and Round Keys to maximize memory bandwidth.
* The "Thunk" Zero-Copy Bypass: A 32-byte payload struct containing a magic flag, real data size, a Unified Memory pointer, and the MAC tag. FastDDS is tricked into serializing and transmitting only these 32 bytes instead of the full payload (e.g., 8MB).

---

## Performance Benchmarking (Pure Cryptographic Execution)

### Evaluation Methodology
To rigorously evaluate the core cryptographic engines, all network communication, middleware routing, and serialization overheads were completely removed from the benchmark. The measurements reflect the pure AES-GCM encryption time required to process the payloads. 

Furthermore, the LTO Fusion middleware hooks were disabled for this specific test. The benchmark strictly compares the standalone cryptographic compute performance.

### Comparison Targets
1. Baseline: Standard OpenSSL EVP AES-256-GCM library (CPU).
2. CPU Optimized: ARM NEON SIMD Engine (Standalone 1-way parallel execution).
3. GPU Accelerated: CUDA Parallel Tree Reduction on NVIDIA Jetson Orin Nano.

### Key Results
* Massive Payload Processing (GPU vs. CPU): For massive payloads (e.g., 8MB), the GPU's Parallel Tree Reduction drastically outperformed both the standard OpenSSL baseline and the ARM NEON 1-way CPU processing. By utilizing Unified Memory (UM), the GPU effectively removed the cryptographic bottleneck for high-resolution sensors without incurring memory copy penalties between the host and device.
* Instruction-Level Optimization (ARM NEON vs. OpenSSL): Even without GPU assistance, the pure ARM NEON SIMD implementations bypassed the deep function call chains inherent to the OpenSSL library, demonstrating significantly lower latency and deterministic execution times for standard payload sizes.
