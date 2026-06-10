#  LTO Fusion: Hardware-Accelerated Standard SROS2 Cryptography

![C++](https://img.shields.io/badge/C++-14%2F17-blue.svg)
![LLVM](https://img.shields.io/badge/LLVM-LTO_Pass-red.svg)
![SROS2](https://img.shields.io/badge/SROS2-Standard_RTPS-green.svg)
![ARM](https://img.shields.io/badge/ARM-NEON_SIMD-orange.svg)

##  Overview
A hyper-optimized, hardware-aware cryptographic architecture for standard SROS2 (ROS2 Security) and FastDDS environments. While traditional SROS2 relies on heavy, call-stack-laden standard cryptographic libraries (e.g., OpenSSL) that cause significant CPU bottlenecks, this project injects a custom LLVM Link-Time Optimization (LTO) pass directly into the middleware's `CryptoTransform` pipeline. 

By replacing the standard encoding/decoding functions with inline, hardware-accelerated ARM NEON SIMD engines, this architecture drastically reduces serialization and encryption latency. Crucially, **it maintains 100% RTPS network compatibility**, allowing for secure, high-throughput communication across multi-host distributed robotic systems (CPS).

---

##  Core Architecture & Components

###  Standard Pipeline LTO Hooks
* **`CryptoFusionPass.cpp`**
  An LLVM LTO pass specifically targeting the standard SROS2 data plane. Instead of bypassing the middleware, it strategically intercepts `encode_serialized_payload` and `decode_serialized_payload` at the IR level, replacing them with highly optimized, in-place SIMD execution wrappers.

###  Hardware-Accelerated Inline Crypto Engine
* **`FusedCryptoWrapper.cpp`**
  The C++ integration wrapper that seamlessly bridges the FastDDS standard crypto interface with the bare-metal SIMD engine (`fuse_inline_enc_payload` / `fuse_inline_dec_payload`). It ensures memory alignment and eliminates unnecessary buffer copies during the RTPS packet construction.
* **`FusedCryptoPayload.h`**
  The core AES-256-GCM cryptographic engine powered by ARM NEON SIMD intrinsics. It processes payload data in 128-byte parallel chunks (`process_128bytes_fused_arm`), utilizing L1-cache key streaming and heterogeneous register allocation to eliminate stack spilling and maximize CPU pipeline efficiency.

###  Middleware Native Integration & Benchmarking
* **`main.cpp`**
  The core benchmarking application that orchestrates the Publisher and Subscriber nodes. It configures the QoS policies and executes the throughput and latency measurements.
* **`AESGCMGMAC_Transform.cpp`**
  Modifications within the native eProsima Fast DDS security plugin layer. It demonstrates the seamless integration point where the LTO hooks capture the active session keys and explicit IVs directly from the standard SROS2 context without breaking the PKI-DH control plane state.
* **`VariablePayloadPubSubTypes.cxx`**
  The FastDDS TypeSupport implementation featuring an innovative **Thunk (Trampoline) pattern**. By explicitly passing a `memcpy` function pointer and a `thunk flag`, it creates a clear optimization boundary. The LLVM pass devirtualizes this indirect call during Link-Time Optimization (LTO), achieving true "One-Shot" execution—fusing Fast-CDR serialization and AES-GCM encryption into a single, intermediate-buffer-free CPU cycle compliant with RTPS standards.
* **`VariablePayload.idl` & Generated Files (`.h`, `.cxx`)**
  The Interface Definition Language (IDL) specification and its generated C++ sources. 
* **`fastddsgen.jar`**
  The eProsima Fast DDS code generator used to compile the IDL specifications into the necessary C++ structures.



---

##  Performance & Optimization Highlights (Jetson Orin Nano)

* **Massive Throughput Gains (Up to 1.73x):** Consistently outperforms the standard SROS2 across all payload scales. At the critical 1024-byte payload mark, LTO Fusion achieves **102,057 msg/s** compared to Pure SROS2's 58,750 msg/s, delivering a ~1.73x performance multiplier.
* **Drastic Latency Reduction & Tail Control:** Slashes Average, P50, and P99 tail latencies. In massive payload scenarios (e.g., 32,768 bytes), LTO Fusion suppresses the average latency to **35.75 µs**—less than half of the standard SROS2 bottleneck (87.38 µs), guaranteeing deterministic real-time execution for robotic systems.
* **Synergistic Step-wise Optimization:** The benchmarks mathematically prove the architectural superiority. While standalone hardware acceleration (8-way NEON) provides significant gains, coupling it with LTO memory optimization (Zero Call-Stack) shatters the framework overhead, pushing the cryptographic pipeline to its absolute hardware limits.
