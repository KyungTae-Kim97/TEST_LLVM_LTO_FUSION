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
