# High-Performance SROS2 Cryptographic Acceleration Framework

![C++](https://img.shields.io/badge/C++-14%2F17-blue.svg)
![LLVM](https://img.shields.io/badge/LLVM-LTO_Pass-red.svg)
![CUDA](https://img.shields.io/badge/CUDA-11.x%2B-green.svg)
![FastDDS](https://img.shields.io/badge/FastDDS-SROS2-green.svg)
![ARM](https://img.shields.io/badge/ARM-NEON_SIMD-orange.svg)

## Overview

Secure, low-latency inter-process communication is a first-order design constraint for modern robotic systems. Robot Operating System 2 (ROS 2) and its security layer SROS2 provide standardized cryptographic protection through DDS Security, but they treat **serialization** and **encryption** as two independent, sequential stages. That separation costs CPU cycles, extra memory copies, and—most critically for real-time control—unpredictable tail latency. For large sensor payloads the trade-off is even sharper: securing them forces you to either pay for costly network-level fragmentation, or take the fast zero-copy shared-memory path, which **skips encryption entirely and writes plaintext to `/dev/shm`**. There is no path that is both secure and zero-copy.

This project closes that gap. It fuses serialization and encryption at the compiler level using **LLVM Link-Time Optimization (LTO)** and custom passes, backed by a hand-written **8-way parallel AES-GCM engine on ARM NEON**. The same fusion is applied to two transport paths—the standard SROS2 network path for small messages, and the zero-copy shared-memory path for large payloads. A hard design constraint throughout: **zero modification to middleware source.** Everything happens at compile and link time through the passes, so the result is a drop-in enhancement that preserves full RTPS wire-format compatibility.

> **Note on scope.** The three modules below are evaluated as **independent experimental configurations**, not as a single runtime system that auto-selects a path. A unified size-based dispatcher is future work; here, each module isolates and measures one layer of the stack.

---

## Why This Is Hard (and Interesting)

Three problems had to be solved, each in a different layer:

1. **Compute.** OpenSSL's AES-GCM carries deep function-call chains and per-message setup cost that dominate at small sizes and cap throughput at large ones. We needed a crypto engine that saturates the hardware.
2. **Fusion across a library boundary.** Serialization (Fast-CDR) and the crypto engine live in separate compilation units. Merging them into one intermediate-buffer-free pass requires optimizing *across* that boundary—something source-level edits cannot achieve without forking the middleware.
3. **A key that lives in the wrong layer.** ROS 2's zero-copy transport is *designed to bypass* the security layer—but the session key is generated *only inside* that layer. Encrypting the zero-copy path means obtaining a key from a layer you never traverse.

---

## 1. GPU_vs_CPU_SIMD_Acceleration

This baseline module isolates the pure cryptographic compute engines—no ROS 2 middleware, no network—to establish which hardware path is actually fastest, and why.

### Core Engines
* **CPU (ARM NEON SIMD):** Up to 8-way parallel execution. The width is bounded by register pressure: AES/GHASH process 16-byte blocks with a serial dependency chain, so we run several independent block streams to keep the pipeline full. At 8-way, eight plaintext blocks, the GHASH key powers, and the AES round keys must stay live in the 32 architectural NEON registers simultaneously—going wider spills to the stack and erases the gain. Round keys are streamed from L1 rather than pinned, and GHASH XOR accumulation is offloaded to general-purpose registers to relieve NEON pressure. The generated hot loop has **no stack frame and no spill** (verified in the emitted AArch64 assembly).
* **GPU (CUDA Zero-Copy Thunk):** A thin host-to-device dispatch that hands the GPU a pointer to the already-serialized buffer via unified memory—no host-device copy—so only the encryption cost is measured. GHASH's sequential dependency is broken with a parallel tree reduction.

### Key Result: on edge hardware, the CPU wins—and the reason matters

On the same Jetson platform, the CPU beats the GPU for this workload. The cause is **not** core count; it is **instruction-set support**. The Cortex-A78AE implements the ARMv8 Cryptography Extension (AESE/AESD/PMULL) directly in silicon—the ARM analogue of Intel's AES-NI. The GPU has no dedicated crypto hardware, so its CUDA kernel must implement AES and GHASH with general-purpose bitwise operations, which makes its massive parallelism inefficient for this specific task.

**Per-Message Encryption Latency (8 MB payload)**
| Configuration | Scope | Latency |
| :--- | :--- | ---: |
| **Jetson CPU (Pure SROS2)** | Encryption | 11.339 ms |
| **Jetson GPU (Thunk)** | Encryption | 28.110 ms |

The takeaway is not "GPU is bad." It is that this workload is gated by crypto primitives the edge GPU lacks. With a dedicated crypto engine, batching many messages and amortizing kernel-launch overhead could shift the balance—but for small, frequent, latency-critical control messages, the in-process CPU path remains the right choice.

![Throughput vs. Data Size](figures/throughput_by_data_size.png)
*Figure 1: LTO fusion combined with varying levels of ARM NEON instruction-level parallelism (1-Way to 8-Way) across data sizes. Note the crossover near 1 KB: the OpenSSL baseline is slowest for small payloads (fixed overhead dominates) but recovers at scale as that overhead amortizes, while the 8-Way fused path stays ahead across the full range.*

---

## 2. ROS2_LTO — Fusing Serialization and Encryption (< 64 KB)

This module applies the 8-way engine to the standard SROS2 network path for small-to-medium payloads.

### How the fusion works
A custom LLVM pass (`CryptoFusionPass`) rewrites a named marker in the Fast-CDR serialization path so that the `memcpy` which copies data becomes the encryption itself—the bytes that land at the destination are **already ciphertext**. There is no separate plaintext buffer written and thrown away; the copy and the encryption are one pass over the data.

Two design points make this non-trivial:

* **Why LTO, not just a pass.** The pass rewrites the copy into a call to the fusion engine, but that engine lives in a separate shared library and its inner routine is `always_inline`. Inlining it into the call site—killing the call overhead and letting it fuse with the surrounding code—requires the caller and the crypto library to be in **one optimization unit**. That is what LTO provides: it compiles everything to bitcode and merges it at link time, so the inline crosses the library boundary. (In practice, LTO was aggressive enough that the crypto entry points had to be force-kept with linker flags—concrete evidence the whole-program optimization is actually running.)
* **Marker-based interception protects the control plane.** Hooking the *generic* serializer would encrypt every RTPS control signal—heartbeats, discovery, ACKNACKs—and break the middleware. Instead the pass targets a named marker that sits only in the payload path. Control traffic stays plaintext; only the bulk payload is encrypted. This is a data-plane-only interception.

On the SROS2 path, the MAC is computed by our engine, but because encryption runs inside the security layer, the standard `SecureDataHeader`/`SecureDataTag` structures are reused to place that MAC on the wire—so no wire-format layout code is written by hand.

### Why a custom engine instead of OpenSSL?

The reasons differ by payload size, and the benchmarks show it honestly. For **small messages**, OpenSSL's fixed overhead—function-call chains and per-message setup—dominates, and the fused engine is several times faster. For **large messages**, OpenSSL actually catches up on raw throughput: that fixed overhead amortizes and its own hardware acceleration shows through (the crossover is visible around 1 KB in Figure 1). This project does *not* claim OpenSSL is slow at scale—it isn't.

The decisive reason is architectural, not raw speed: **OpenSSL is a black box to the toolchain.** It can be *called*, but it cannot be *fused*—inlined into the serialization loop, or injected into the zero-copy path at the LLVM IR level. A custom AES-GCM engine, implemented against the same ARMv8 Crypto Extension instructions (AESE, PMULL) that OpenSSL uses under the hood, is something LTO can inline and the passes can control. The custom part is the *fusion and the data path*, not the cryptographic math. (Formal constant-time / side-channel auditing is future work.)

### Performance
The LTO Fusion 8-Way configuration outperforms standard SROS2 across payload sizes, in both average and—more importantly for real-time systems—tail latency.

![Publisher-Side Throughput vs. Payload Size](figures/publisher_throughput_by_payload_size.png)
*Figure 2: Publisher-side throughput; LTO Fusion 8-Way vs. pure SROS2.*

---

## 3. Data_sharing_LTO — Secure Zero-Copy Transport (≥ 64 KB)

For large payloads, ROS 2's native zero-copy Data-Sharing transport writes directly to `/dev/shm`—but it bypasses the security layer, so the data goes out in plaintext. Securing it without breaking zero-copy is the hardest of the three problems, because the session key is generated only inside the layer that this path skips.

### The session-key "Heist"
An LLVM pass (`ZeroCopyHeistPass`) resolves the dilemma at compile time. It finds the key-exchange function by name and injects a call at the point where it returns—the exact moment the crypto handle (the object holding the key material) has just been created. The injected code grabs that handle, derives the session key, and stashes it in a global context. Both the sender and receiver do this at their key-exchange step. **Zero source modification**—it is all IR injection at the return site.

**Deterministic TX/RX synchronization without sending secrets.** Both sides derive the same session key from a *public* identifier (the sender key ID), running the same derivation with the same key material—so they arrive at the identical key **without the secret ever crossing the wire.**

**IV construction (no nonce reuse).** The 12-byte IV is split: the top 4 bytes are the public sender ID (spatial separation—different writers never collide), and the bottom 8 bytes are a per-payload atomic counter (temporal separation—every message is unique). The sender writes that counter into the shared-memory tail right after the MAC, so the receiver reconstructs the exact IV independently, with no network synchronization and robustness to packet loss.

### Performance
Relocating the transfer to shared memory removes the fragmentation bottleneck that caps standard SROS2 at large sizes. The fused path then tracks the unencrypted zero-copy ceiling closely at small sizes and bends toward an **encryption-bound** ceiling as payloads grow (≈ 11.8 Gbps at 4 MB)—i.e., beyond a point the AES-256-GCM computation, not shared-memory bandwidth, is the limiting factor. Crucially, its tail latency stays far more stable than the baseline's.

![P99 latency comparison across payload sizes](figures/data-sharing-p99_latency2.png)
*Figure 3: P99 tail-latency comparison; the Data-Sharing LTO Fusion path suppresses the latency spikes that the baseline exhibits at large payloads, while adding encryption.*

---

## Why It Matters

The headline is not just higher average throughput—it is **predictability**. Real-time robots are designed against worst-case latency, not average: a control loop fails on the one late message, not the average one. Across large payloads the baseline's P99 tail is erratic, while the fused path keeps P99 rising smoothly and proportionally with payload size. Reducing that tail variance is what turns raw speed into something a deadline-driven system can actually rely on. (The measurements here characterize the latency distribution, not a specific control loop; the contribution is removing a jitter source that would otherwise threaten deadlines.)

## Design Notes & Limitations

* **Two independent paths, not an auto-router.** Path selection by message size is described conceptually; a unified runtime dispatcher is future work. The 64 KB boundary is not a tuning knob—it is the hard RTPS/DDS per-packet limit, above which the single-pass network fusion cannot go.
* **Asymmetric TX/RX by design.** Serialization and encryption are fused on the transmit side. Decryption is *not* fused with deserialization: AES-GCM requires verify-then-decrypt, so releasing plaintext before the MAC is verified would violate the cryptographic doom principle. The receive side keeps the standard path, which also preserves drop-in compatibility.
* **Session-key rotation.** The IV is refreshed per payload, so there is no nonce reuse; following SROS2's periodic session-key rotation on the zero-copy path is future work.

## Repository Structure

```
GPU_vs_CPU_SIMD_Acceleration/   # Module 1: isolated crypto compute engines (CPU NEON vs CUDA)
ROS2_LTO/                       # Module 2: serialization+encryption fusion, network path (<64KB)
Data_sharing_LTO/               # Module 3: secure zero-copy transport, /dev/shm path (>=64KB)
figures/                        # Benchmark plots
```

## Tech Stack

C++14/17 · LLVM (custom LTO passes) · ARM NEON intrinsics (ARMv8 Crypto Extension) · CUDA (unified memory) · FastDDS / SROS2 · AES-256-GCM · Jetson Orin Nano (Cortex-A78AE)
