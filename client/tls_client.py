#!/usr/bin/env python3

import ssl
import socket
import sys
import os
import time
import curses
from datetime import datetime
from threading import Thread, Event

# ANSI color codes
GREEN = '\033[0;32m'
YELLOW = '\033[0;33m'
BLUE = '\033[0;34m'
RED = '\033[0;31m'
RESET = '\033[0m'

class TLSClient:
    def __init__(self, host='localhost', port=8443):
        self.host = host
        self.port = port
        self.cert_path = os.path.join("..", "certs", "server.crt")
        self.secure_socket = None
        self.reconnect_attempts = 3
        self.reconnect_delay = 2  # seconds
        self.stop_event = Event()
        self.screen = None
        
    def setup_ui(self):
        """Initialize curses UI"""
        self.screen = curses.initscr()
        curses.start_color()
        curses.init_pair(1, curses.COLOR_GREEN, curses.COLOR_BLACK)
        curses.init_pair(2, curses.COLOR_YELLOW, curses.COLOR_BLACK)
        curses.init_pair(3, curses.COLOR_RED, curses.COLOR_BLACK)
        curses.noecho()
        curses.cbreak()
        self.screen.keypad(True)
        self.screen.scrollok(True)
        self.screen.clear()
        
    def cleanup_ui(self):
        """Cleanup curses UI"""
        if self.screen:
            self.screen.keypad(False)
            curses.nocbreak()
            curses.echo()
            curses.endwin()
        
    def check_certificate(self):
        """Check if certificate file exists"""
        if not os.path.exists(self.cert_path):
            self.log_message(f"Error: Certificate file not found.", 3)
            self.log_message(f"Expected: {self.cert_path}", 3)
            self.log_message("Run cert_generator.sh first to create the certificate.", 3)
            return False
        return True
        
    def connect_to_server(self):
        """Connect to the TLS server with retry logic"""
        for attempt in range(self.reconnect_attempts):
            try:
                # Create a TCP/IP socket
                client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client_socket.settimeout(10)
                
                # Set up SSL context
                context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
                context.check_hostname = True
                context.load_verify_locations(self.cert_path)
                
                # Wrap the socket with SSL/TLS
                self.secure_socket = context.wrap_socket(client_socket, server_hostname='localhost')
                
                # Connect to server
                self.log_message(f"Connecting to {self.host}:{self.port}... (Attempt {attempt + 1})", 2)
                self.secure_socket.connect((self.host, self.port))
                self.log_message("Connected successfully!", 1)
                
                return True
                
            except (ssl.SSLError, ConnectionRefusedError, socket.timeout) as e:
                self.log_message(f"Connection attempt {attempt + 1} failed: {str(e)}", 3)
                if attempt < self.reconnect_attempts - 1:
                    self.log_message(f"Retrying in {self.reconnect_delay} seconds...", 2)
                    time.sleep(self.reconnect_delay)
                else:
                    self.log_message("Maximum reconnection attempts reached.", 3)
                    
        return False
    
    def log_message(self, message, color_pair=0):
        """Log a message to the UI"""
        if self.screen:
            max_y, max_x = self.screen.getmaxyx()
            y, x = self.screen.getyx()
            if y >= max_y - 1:
                self.screen.scroll(1)
                y = max_y - 2
            self.screen.addstr(y, 0, message + "\n", curses.color_pair(color_pair))
            self.screen.refresh()
    
    def receive_messages(self):
        """Background thread for receiving messages"""
        while not self.stop_event.is_set():
            try:
                data = self.secure_socket.recv(1024)
                if not data:
                    self.log_message("Server disconnected.", 3)
                    break
                if data.decode() == "ping":
                    continue  # Ignore keepalive messages
                self.log_message(f"Server: {data.decode()}", 1)
            except socket.timeout:
                continue  # Just try again
            except (ssl.SSLError, socket.error) as e:
                if not self.stop_event.is_set():
                    self.log_message(f"Error receiving message: {e}", 3)
                    break
    
    def send_message(self, message):
        """Send a message to the server"""
        try:
            self.secure_socket.send(message.encode())
        except (socket.error, ssl.SSLError) as e:
            self.log_message(f"Error sending message: {e}", 3)
            return False
        return True
    
    def interactive_session(self):
        """Run an interactive session with the server"""
        try:
            # Start message receiver thread
            receiver_thread = Thread(target=self.receive_messages)
            receiver_thread.daemon = True
            receiver_thread.start()
            
            # Main input loop
            while not self.stop_event.is_set():
                try:
                    self.screen.addstr(curses.LINES-1, 0, "> ")
                    self.screen.clrtoeol()
                    curses.echo()
                    message = self.screen.getstr(curses.LINES-1, 2).decode()
                    curses.noecho()
                    
                    if message.lower() == 'exit':
                        break
                        
                    if not self.send_message(message):
                        break
                        
                except curses.error:
                    continue
                    
        except KeyboardInterrupt:
            self.log_message("Client stopped by user", 2)
        finally:
            self.stop_event.set()
            receiver_thread.join(timeout=1.0)
    
    def run(self):
        """Run the TLS client"""
        try:
            self.setup_ui()
            
            # Check certificate
            if not self.check_certificate():
                return
            
            # Connect to server
            if not self.connect_to_server():
                return
            
            # Run interactive session
            self.interactive_session()
            
        finally:
            # Cleanup
            if self.secure_socket:
                self.secure_socket.close()
            self.cleanup_ui()
            self.log_message("Connection closed", 1)

if __name__ == "__main__":
    client = TLSClient()
    client.run()