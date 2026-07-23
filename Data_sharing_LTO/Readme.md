# LTO Fusion: Data-sharing for ROS2/FastDDS

![C++](https://img.shields.io/badge/C++-14%2F17-blue.svg)
![LLVM](https://img.shields.io/badge/LLVM-LTO_Pass-red.svg)
![FastDDS](https://img.shields.io/badge/FastDDS-SROS2-green.svg)
![ARM](https://img.shields.io/badge/ARM-NEON_SIMD-orange.svg)

##  Overview
A high-performance, hardware-aware secure architecture for ROS2 and FastDDS. This project resolves the critical security vulnerability in the Data-Sharing (Zero-Copy) mechanism where payloads bypass the SROS2 `CryptoTransform` layer. By utilizing LLVM Link-Time Optimization (LTO) passes and ARM NEON SIMD intrinsics, it fuses AES-256-GCM encryption directly into the `/dev/shm` memory copy cycle, achieving 0ns synchronization overhead and pushing throughput to the hardware's physical memory bandwidth limits (1.4 GB/s for 4MB payloads).

---

##  Core Architecture & Components

###  Compiler Hooks (LLVM LTO Passes)
* **`CryptoFusionPass.cpp`**
  An LLVM LTO pass that intercepts Fast-CDR serialization and deserialization at the IR level. It replaces standard memory copy instructions (`memcpy`) with hardware-accelerated, inline crypto wrappers.
* **`ZeroCopyHeistPass.cpp`**
  An LLVM LTO pass targeting the SROS2 control plane (`KeyFactory` and `KeyExchange`). It injects return-instruction hooks to stealthily capture cryptographic handles during the standard PKI-DH handshake.

###  Hardware-Accelerated Crypto Engine & OS Integration
* **`FusedCryptoPayload.h`**
  The core AES-256-GCM cryptographic engine optimized with ARM NEON SIMD intrinsics. It features L1-cache key streaming and inline GHASH accumulation to maximize throughput and eliminate stack spilling.
* **`FusedCryptoWrapper.cpp`**
  A lock-free integration wrapper managing 0ns atomic key synchronization (`std::atomic`). It orchestrates direct `/dev/shm` access and enforces a stateless memory layout by appending the explicit IV and MAC directly to the payload tail.
* **`ZeroCopyHeist.cpp`**
  The dynamic key extraction logic that intercepts legitimate SROS2 cryptographic handles. It filters for payload-protected channels and preemptively derives the AES session keys for the data plane bypass.

###  Middleware Integration & Benchmarking
* **`main.cpp`**
  The core benchmarking application that orchestrates the Publisher and Subscriber nodes. It configures the QoS policies (enabling Data-Sharing) and executes the throughput and latency measurements.
* **`VariablePayload.idl` & Generated Files (`.h`, `.cxx`)**
  The Interface Definition Language (IDL) specification and its generated C++ sources. 
* **`VariablePayloadPubSubTypes.cxx`**
  The FastDDS TypeSupport implementation, specifically extended to allocate a 5MB shared memory chunk to accommodate massive payload zero-copy transfers. Modified with specific byte offsets (`jump(+24)`) to bypass middleware headers and accommodate the fused IV/MAC tail.
* **`fastddsgen.jar`**
  The eProsima Fast DDS code generator used to compile the IDL specifications into the necessary C++ structures.

---

##  Performance Evaluation (Jetson Orin Nano)

* **Throughput:** Achieved **1.4 GB/s** for 4MB payloads (an 81% improvement over Pure SROS2's 772 MB/s).
* **Latency:** Processed 4MB payloads in **2.85ms**, drastically reducing the 5.19ms delay of standard SROS2 by eliminating redundant middleware network stack copies.
* **Efficiency:** Achieved near-theoretical hardware limits, isolating pure cryptographic overhead to merely ~2.0ms compared to unsecured pure shared memory transfers.

**Latency and Throughput Comparison Across Payload Sizes**  
*(Pure SROS2 vs. Data-Sharing with LTO Fusion vs. Pure Data-Sharing without encryption)*

| Configuration | Metric | 64KB | 128KB | 256KB | 512KB | 1MB | 2MB | 4MB |
| :--- | :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| **Pure SROS2** | Avg Latency (ns) | 204,577 | 286,891 | 441,124 | 738,586 | 1,444,129 | 2,631,685 | 5,194,649 |
| | P99 Latency (ns) | 510,816 | 840,416 | 1,493,760 | 1,153,152 | 3,388,768 | 3,659,360 | 10,350,560 |
| | Throughput (Gbps) | 2.563 | 3.655 | 4.754 | 5.679 | 5.805 | 6.375 | 6.476 |
| **Data-Sharing LTO Fusion** | Avg Latency (ns) | 82,180 | 112,021 | 201,898 | 379,045 | 729,778 | 1,432,878 | 2,845,151 |
| | P99 Latency (ns) | 252,928 | 193,440 | 289,888 | 476,480 | 867,104 | 1,770,016 | 3,931,488 |
| | Throughput (Gbps) | 6.380 | 9.361 | 10.387 | 11.065 | 11.492 | 11.710 | 11.777 |
| **Pure Data-Sharing (No Encryption)** | Avg Latency (ns) | 76,290 | 98,492 | 122,761 | 174,015 | 247,221 | 434,698 | 810,467 |
| | P99 Latency (ns) | 219,680 | 329,088 | 434,048 | 394,144 | 420,192 | 677,760 | 1,194,464 |
| | Throughput (Gbps) | 6.872 | 10.646 | 17.083 | 24.104 | 33.932 | 38.588 | 41.405 |
