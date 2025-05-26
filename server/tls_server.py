#!/usr/bin/env python3

import ssl
import socket
import sys
import os
from threading import Thread, Lock
from datetime import datetime

# ANSI color codes
GREEN = '\033[0;32m'
YELLOW = '\033[0;33m'
BLUE = '\033[0;34m'
RED = '\033[0;31m'
RESET = '\033[0m'

class TLSServer:
    def __init__(self, host='localhost', port=8443):
        self.host = host
        self.port = port
        self.cert_path = os.path.join("..", "certs", "server.crt")
        self.key_path = os.path.join("..", "certs", "server.key")
        self.clients = []
        self.clients_lock = Lock()
        self.running = True

    def check_certificates(self):
        if not os.path.exists(self.cert_path) or not os.path.exists(self.key_path):
            print("Error: Certificate files not found.")
            print(f"Expected: {self.cert_path} and {self.key_path}")
            print("Run cert_generator.sh first to create the certificates.")
            return False
        return True

    def handle_client(self, client_socket, address):
        try:
            print(f"\n{GREEN}[+] New client connected: {address[0]}:{address[1]}{RESET}")
            client_socket.settimeout(300)  # 5 minutes timeout
            
            while self.running:
                try:
                    data = client_socket.recv(1024)
                    if not data:
                        break
                    decoded_message = data.decode().strip()
                    if decoded_message:
                        # Format the message with timestamp
                        timestamp = datetime.now().strftime("%H:%M:%S")
                        message = f"\n[{timestamp}] {BLUE}Client {address[0]}:{address[1]}:{RESET} {decoded_message}"
                        print(message)
                        self.broadcast(message, client_socket)
                except socket.timeout:
                    try:
                        client_socket.send(b"ping")
                        continue
                    except:
                        print(f"{YELLOW}[-] Client {address[0]}:{address[1]} timed out{RESET}")
                        break
                except (ssl.SSLError, socket.error) as e:
                    print(f"\n{RED}[-] Error with {address}: {e}{RESET}")
                    break
        finally:
            with self.clients_lock:
                if client_socket in self.clients:
                    self.clients.remove(client_socket)
            try:
                client_socket.close()
            except:
                pass
            print(f"\n{YELLOW}[-] Client disconnected: {address[0]}:{address[1]}{RESET}")

    def broadcast(self, message, sender_socket=None):
        with self.clients_lock:
            for client in self.clients:
                if client != sender_socket:
                    try:
                        client.send(message.encode())
                    except:
                        continue

    def run(self):
        if not self.check_certificates():
            return

        try:
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            context.load_cert_chain(self.cert_path, self.key_path)

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
                server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                # Set server socket timeout
                server_socket.settimeout(60)  # 60 seconds timeout
                server_socket.bind((self.host, self.port))
                server_socket.listen(5)
                
                print(f"TLS Server running on {self.host}:{self.port}")
                print("Press Ctrl+C to stop the server")

                while self.running:
                    print("Waiting for a secure connection...")
                    try:
                        client_sock, client_addr = server_socket.accept()
                        secure_client = context.wrap_socket(client_sock, server_side=True)
                        
                        with self.clients_lock:
                            self.clients.append(secure_client)
                        
                        print(f"Secure connection established with {client_addr[0]}:{client_addr[1]}")
                        client_thread = Thread(target=self.handle_client, 
                                            args=(secure_client, client_addr))
                        client_thread.daemon = True
                        client_thread.start()
                    except (ssl.SSLError, socket.error) as e:
                        print(f"Connection error: {e}")
                        continue

        except KeyboardInterrupt:
            print("\nServer shutting down...")
        except Exception as e:
            print(f"Server error: {e}")
        finally:
            self.running = False
            with self.clients_lock:
                for client in self.clients:
                    try:
                        client.close()
                    except:
                        pass
            print("Server shut down")

if __name__ == "__main__":
    server = TLSServer()
    server.run()