import socket
import hmac
from hashlib import md5

SECRET_KEY = b'!@#$%^'

def generate_hmac(message):
    # Create an HMAC object using the secret key and SHA-256 hash algorithm
    key = hmac.new(SECRET_KEY, digestmod=md5)
    # Update the HMAC with the encoded message
    key.update(message.encode('utf-8'))
    # Return the digest (hash) of the HMAC
    return key.digest()

def start_client():
    try:
        # Create a TCP/IP socket for the client
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Connect to the server at localhost:12345
        client_socket.connect(('localhost', 12345))

        while True:
            try:
                # Prompt the user to enter a message
                message = input("Enter your message (type 'exit' to quit): ")

                # Check if the user wants to exit the client
                if message.lower() == 'exit':
                    break

                # Generate an HMAC for the user's message
                message_hmac = generate_hmac(message)
                # Convert the HMAC to a hexadecimal representation
                hex_message_hmac = message_hmac.hex()
                # Format the data to be sent to the server: "message|hex_message_hmac\n"
                data_to_send = f"{message}|{hex_message_hmac}\n"
                # Send the formatted data to the server
                client_socket.send(data_to_send.encode('utf-8'))

            except KeyboardInterrupt:
                # Handle keyboard interrupt (Ctrl+C) for graceful client shutdown
                print("Client shutting down...")
                break

        print("Exiting client.")

    except Exception as e:
        # Handle exceptions that may occur during client operation
        print(f"Error: {e}")

    finally:
        # Close the client socket in the finally block to ensure proper cleanup
        client_socket.close()

if __name__ == "__main__":
    # Start the client if the script is executed as the main program
    start_client()
