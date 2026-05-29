CC = x86_64-w64-mingw32-g++
AS = nasm

# Obfuscation key
OBF_KEY = 145

#OPSEC & Optimization Flags
CFLAGS = -std=c++14 -masm=intel -static -I. \
         -DOBF_KEY=$(OBF_KEY) \
         -s -Os -fno-exceptions -fno-rtti -mwindows \
	 	 -fno-ident -Wl,--build-id=none

ASFLAGS = -f win64
LIBS = -lwininet -lws2_32

OBJS = Core/main.o Core/api_resolve.o Core/syscalls.o Core/dispatcher.o \
       Core/syscalls_asm.o \
       Crypto/encryption.o \
       Evasion/mutex_lock.o Evasion/timestomp.o \
       Modules/file_io.o Modules/injection.o Modules/persistence.o Modules/recon.o Modules/suicide.o \
       Network/c2_server.o \
       Utils/helpers.o

astaroth.exe: $(OBJS)
	$(CC) $(OBJS) -o astaroth.exe $(CFLAGS) $(LIBS)

Core/syscalls_asm.o: Core/syscalls_asm.asm
	$(AS) $(ASFLAGS) $< -o $@

%.o: %.cpp
	$(CC) -c $< -o $@ $(CFLAGS)

clean:
	rm -f $(OBJS) astaroth.exe
