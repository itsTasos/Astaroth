import sys
import pefile

def sanitize_pe(target_file):
    try:
      
        pe = pefile.PE(target_file)
        
        original_timestamp = pe.FILE_HEADER.TimeDateStamp
        print(f"[*] Original TimeDateStamp: {original_timestamp} (0x{original_timestamp:08x})")
        

        pe.FILE_HEADER.TimeDateStamp = 0
        
 
        pe.OPTIONAL_HEADER.CheckSum = 0
        
        
        pe.write(filename=target_file)
        print(f"[+] Successfully sanitized PE metadata for: {target_file}")
        
    except FileNotFoundError:
        print(f"[!] Error: File '{target_file}' not found.")
        sys.exit(1)
    except pefile.PEFormatError:
        print("[!] Error: File is not a valid PE document.")
        sys.exit(1)

if __name__ == "__main__":
    
    if len(sys.argv) < 2:
        print("Usage: python pe_sanitizer.py <target.exe>")
        sys.exit(1)
        
    target_exe = sys.argv[1]
    sanitize_pe(target_exe)
