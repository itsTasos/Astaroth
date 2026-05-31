<div align="center">
  <h3><em>The Revealer of Secrets, The Architect of Shadows</em></h3>
  <p>A low-level Command & Control implant build for stealth and reconaisance.</p>
</div>

<br/>

<div align="center">
  <img src="https://img.shields.io/badge/Language-C++17-blue.svg" alt="Language">
  <img src="https://img.shields.io/badge/Language-Assembly-red.svg" alt="Assembly">
  <img src="https://img.shields.io/badge/Platform-Windows-lightgrey.svg" alt="Platform">
  <img src="https://img.shields.io/badge/Status-Active_Development-success.svg" alt="Status">
</div>

---

## Project Overview

Astaroth is a custom C2 implant built from scratch to study how Endpoint Detection and Response (EDR) telemetry actually works under the hood. Instead of relying on standard Windows APIs that are easily hooked, it attempts to operate entirely at the Native API layer. 

Core idea: drop the high-level abstractions. By combining dynamic syscall resolution (Hell's Gate/Halo's Gate), custom PE parsing, and direct NTDLL memory management, the payload aims to completely decouple itself from the Import Address Table (IAT) and standard user-land monitoring. It is a practical exercise in low-level evasion and C++17 system programming.

---

## Core Features

Astaroth is engineered for elite Red Team operations, focusing on evasion, stability, and deep reconnaissance.

*   **[ ❖ ] Dynamic API Resolution & Direct System Calls**
    *   No static imports. Windows APIs are resolved dynamically at runtime using custom string hashing.
    *   Implements **Hell's Gate** and **Halo's Gate** to dynamically resolve System Service Numbers (SSNs) and execute direct system calls, effectively bypassing NTDLL unhooking and user-land EDR hooks.
*   **[ ❖ ] Strict Native Memory Management & OPSEC**
    *   **Direct NTDLL Heap Allocation::** Bypasses standard kernel32.dll memory functions (and the architectural pitfalls of Forwarded Exports) by dynamically resolving RtlAllocateHeap and RtlFreeHeap directly from the ntdll.dll subsystem.
    *   **Stack-Exhaustion Prevention:** Completely eliminates brittle stack allocations (e.g., _alloca) in favor of robust Native Heap management. This ensures absolute stability during large I/O operations (e.g., streaming large cmd.exe outputs) without triggering STATUS_STACK_OVERFLOW exceptions.
    *   **Telemetry Reduction:** By operating memory allocations at the lowest possible User-Mode layer, it evades the standard API hooking and memory-scanning telemetry associated with high-level C-Runtime (CRT) or Win32 memory APIs.
*   **[ ❖ ] Stealth & Evasion**
    *   **Timestomping:** Clones creation, access, and write times from legitimate binaries (e.g., `kernel32.dll`) to blend in.
    *   **CRT Avoidance:** Uses custom implementations for standard library functions (`custom_memcpy`, `custom_wcsicmp`) to prevent hooks on C-Runtime calls.
    *   **Anti-Analysis:** Single-instance execution via mutex locks, hidden console windows, and a blacklist checker for suspicious processes (e.g., `MsMpEng.exe`, `wireshark.exe`).
*   **[ ❖ ] In-Memory Evasion & Payload Execution**
    *   **Section-Based Injection:** Employs `NtCreateSection`, `NtMapViewOfSection`, and `NtCreateThreadEx` to map payloads locally as RW, then remotely into targets as RX, completely avoiding suspicious RWX memory pages.
*   **[ ❖ ] Secure C2 Communications & Persistence**
    *   **RSA-AES Exchange:** Employs an RSA-exchanged AES-256 CBC encrypted channel (via Windows CNG APIs) for all commanding and beaconing.
    *   **Jitter Delays:** `smart_sleep` implementation for randomized beaconing jitter.
    *   **Silent Persistence:** Safe self-migration to `%APPDATA%` as a hidden/system file, establishing persistence via direct registry syscalls to the `UserInitMprLogonScript` environment variable.

---

## Architecture & Modules

The Astaroth codebase is modularized for rapid expansion and structured execution:

*   **`Core`**: Contains the `dispatcher` for routing commands (e.g., `whoami`, `cat`, `inject`), `api_resolve` for building the custom `API_TABLE`, and `syscalls` handling the raw ASM execution of Hell's Gate/Halo's Gate.
*   **`Crypto`**: Cryptographic wrappers managing AES-256 session keys and RSA public key encryption.
*   **`Evasion`**: Contains `timestomp` logic and `mutex_lock` single-instance enforcement.
*   **`Modules`**: 
    *   `recon`: Host enumeration, privilege checks, and native user SID retrieval.
    *   `injection`: Stealthy section-based process injection techniques.
    *   `persistence`: Registry-based survival mechanisms.
    *   `suicide`: Self-deletion routine (`burn` command) to wipe the implant from disk.
*   **`Network`**: `c2_server.cpp` manages bot-side network loops with exponential backoff and encrypted traffic routing.
*   **`C2_Server.py`**: The Team Server backend written in Python 3. It utilizes a multithreaded architecture for asynchronous command broadcasting, interactive bot selection, and RSA/AES decryption of incoming traffic.

---

##  Quick Start / Installation

### Prerequisites

To compile Astaroth, ensure you have the following toolchain installed:

*   **MSVC (Microsoft Visual C++):** Ensure the `cl.exe` compiler is in your PATH.
*   **NASM (Netwide Assembler):** Required for compiling the custom `syscalls.asm` stub.
*   **Python 3.x:** For running `C2_server.py` and managing dependencies (`cryptography` package).

### Compilation

Clone the repository and build the implant using the provided Makefile.

Before compiling the implant, you must generate the RSA key pair used to secure the C2 communications.

1. Run the included key generation script to generate your unique public/private key pair.
2. The script will output a C-style byte array of your Public Key.
3. Copy this key blob and paste it into the implant's source code (within the `Crypto\encryption.cpp`) replacing the default placeholder.
4. Ensure the generated private key (`.pem` file) remains strictly on the Team Server side.

```powershell
# Compile the implant
make
```

### Basic Usage

1. **Start the Team Server:** Ensure `c2_private.pem` is generated and accessible by the Python server.
```bash
python3 C2_server.py
```
2. **Deploy the Implant:** Execute the compiled Astaroth executable on the target host. It will automatically resolve APIs, perform timestomping, install persistence, and beacon back to the Team Server.

---

## Author's Note & Contributions

I do not claim that Astaroth introduces groundbreaking, never-before-seen APT technologies. It is a research endeavor where I attempted to implement these complex concepts as robustly and cleanly as possible.

Because this is a continuous learning process, the codebase is completely open to scrutiny. If you are a fellow researcher, developer, or reverse engineer, contributions are highly encouraged. Feel free to open an Issue or submit a Pull Request.

---

## Legal Disclaimer

> [!CAUTION]
> **Astaroth is created strictly for authorized Red Teaming, Penetration Testing, and educational purposes.**
>
> The developers and contributors of this project assume no liability and are not responsible for any misuse or damage caused by this program. You must have explicit, written permission from the target organization before utilizing this tool against their infrastructure. Do not use Astaroth for illegal, malicious, or unauthorized activities.
