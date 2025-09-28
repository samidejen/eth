# server.py (Version 2.0 - TLS Enabled)
import socket
import threading
import select
import ssl

CERT_FILE = '/home/testat/cert.pem'  # Use the full path to your certificate
KEY_FILE = '/home/testat/key.pem'    # Use the full path to your key file

def handle_client(tls_client_socket):
    try:
        # We now receive the DECRYPTED data from the secure channel
        destination_header = tls_client_socket.recv(4096).decode()
        dest_host, dest_port = destination_header.split(':')
        dest_port = int(dest_port)

        print(f"[Server] Received request to connect to {dest_host}:{dest_port}")

        # Connect to the actual destination (e.g., google.com)
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.connect((dest_host, dest_port))
        
        print(f"[Server] Connection to {dest_host} established.")
        # Send a simple "OK" back through the ENCRYPTED channel
        tls_client_socket.sendall(b"OK")

        # Begin forwarding data in both directions
        forward_data(tls_client_socket, server_socket)

    except Exception as e:
        print(f"[Server] Error: {e}")
    finally:
        tls_client_socket.close()

def forward_data(sock1, sock2):
    sockets = [sock1, sock2]
    while True:
        try:
            readable, _, exceptional = select.select(sockets, [], sockets)
            if exceptional or not readable:
                break
            for s in readable:
                data = s.recv(4096)
                if not data:
                    return
                if s is sock1:
                    sock2.sendall(data)
                else:
                    sock1.sendall(data)
        except:
            break

def main():
    HOST = '0.0.0.0'
    PORT = 443 #The port we use to connect with the client and also we can use it in firewall for incoming requests.

   
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    try:
        context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
    except FileNotFoundError:
        print(f"[ERROR] Certificate files not found!")
        print(f"Please generate them using openssl and check the paths in the script.")
        return
    
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen(5)
    print(f"[*] TLS Server listening on {HOST}:{PORT}")

    while True:
        client, addr = server.accept()
        print(f"[*] Accepted connection from {addr[0]}:{addr[1]}")
        try:
            tls_client_socket = context.wrap_socket(client, server_side=True)
            client_handler = threading.Thread(target=handle_client, args=(tls_client_socket,))
            client_handler.start()
        except ssl.SSLError as e:
            print(f"[Server] SSL Error during handshake: {e}. Dropping connection.")
            client.close()

if __name__ == '__main__':
    main()
