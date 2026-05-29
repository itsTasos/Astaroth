from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import struct

def generate_c2_keys():
    print("[*] Generating RSA-2048 Keypair...")
    
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open("c2_private.pem", "wb") as f:
        f.write(pem_private)
    print("[+] Saved c2_private.pem")

    public_key = private_key.public_key()
    numbers = public_key.public_numbers()

    n = numbers.n.to_bytes(256, byteorder='big')
    e = numbers.e.to_bytes(3, byteorder='big')

    magic = b"RSA1"
    bit_length = 2048
    cb_public_exp = len(e)
    cb_modulus = len(n)
    cb_prime1 = 0
    cb_prime2 = 0

    header = struct.pack("<4sIIIII", magic, bit_length, cb_public_exp, cb_modulus, cb_prime1, cb_prime2)
    
    blob = header + e + n

    c_array = ", ".join([f"0x{byte:02X}" for byte in blob])
    
    print("\n[+] Key Blob")
    print("-" * 50)
    print(f"const BYTE RsaPublicKeyBlob[] = {{\n    {c_array}\n}};")
    print("-" * 50)

if __name__ == "__main__":
    generate_c2_keys()