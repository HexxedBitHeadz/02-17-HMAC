import socket
import hmac
from hashlib import sha256

SECRET_KEY = b'1tsasecret!'

def generate_hmac(message):
    # Create an HMAC object using the secret key and SHA-256 hash algorithm
    key = hmac.new(SECRET_KEY, digestmod=sha256)
    # Update the HMAC with the encoded message
    key.update(message.encode('utf-8'))
    # Return the digest (hash) of the HMAC
    return key.digest()

def verify_and_decode_message(received_data):
    try:
        # Split the received data into the message and its corresponding HMAC
        received_message, received_hex_hmac = received_data.split("|")
        
        # Convert the received hexadecimal HMAC back to bytes
        received_hmac = bytes.fromhex(received_hex_hmac)

        # Generate the HMAC for the received message on the server side
        calculated_hmac = generate_hmac(received_message)

        # Compare the calculated HMAC with the received HMAC for integrity verification
        if hmac.compare_digest(calculated_hmac, received_hmac):
            print("Message integrity verified.")
            print(f"Received message: {received_message}")
        else:
            print("Message integrity check failed.")

    except Exception as e:
        # Handle exceptions that may occur during decoding or verification
        print(f"Error decoding message: {e}")

def start_server():
    # Create a TCP/IP socket for the server
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        # Bind the socket to a specific address and port
        server_socket.bind(('0.0.0.0', 12345))
        # Listen for incoming connections with a backlog of 1
        server_socket.listen(1)
        print("Server listening on port 12345...")

        while True:
            try:
                # Accept a new connection from a client
                client_socket, addr = server_socket.accept()
                print(f"Connection from {addr}")

                while True:
                    # Receive data from the client in chunks of 1024 bytes
                    data = client_socket.recv(1024)
                    if not data:
                        # Break from the inner loop if no more data is received
                        break

                    # Decode the received data into a string and remove leading/trailing whitespaces
                    received_data = data.decode('utf-8').strip()
                    print(f"Received data: {received_data}")

                    # Check if the data includes the delimiter "|"
                    if "|" not in received_data:
                        print("Exiting client.")
                        break

                    # Verify the integrity and decode the received message
                    verify_and_decode_message(received_data)

            except KeyboardInterrupt:
                # Handle keyboard interrupt (Ctrl+C) for graceful server shutdown
                print("Server shutting down...")
                break

            except Exception as e:
                # Handle exceptions that may occur during message processing
                print(f"Error processing message: {e}")

            finally:
                # Close the client socket in the inner loop
                client_socket.close()

    except Exception as e:
        # Handle exceptions that may occur during server startup
        print(f"Error starting server: {e}")

    finally:
        # Close the server socket in the outer loop
        server_socket.close()

if __name__ == "__main__":
    # Start the server if the script is executed as the main program
    start_server()
