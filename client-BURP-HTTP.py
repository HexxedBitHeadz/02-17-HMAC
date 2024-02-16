import requests
import hmac
from hashlib import md5

SECRET_KEY = b'!@#$%^'
BURP_PROXY = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}

def generate_hmac(message):
    key = hmac.new(SECRET_KEY, digestmod=md5)
    key.update(message.encode('utf-8'))
    return key.digest()

def start_client():
    try:
        while True:
            try:
                message = input("Enter your message (type 'exit' to quit): ")

                if message.lower() == 'exit':
                    break

                message_hmac = generate_hmac(message)
                hex_message_hmac = message_hmac.hex()
                data_to_send = f"{message}|{hex_message_hmac}"

                # Send the request through the Burp Suite proxy
                url = 'http://localhost:12345'  # Replace with your server URL
                response = requests.post(url, data=data_to_send, proxies=BURP_PROXY, verify=False)
                print(response)

            except KeyboardInterrupt:
                print("Client shutting down...")
                break

        print("Exiting client.")

    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    start_client()

