import socket
import json
import struct
import sys

def send_quote(host='localhost', port=3443, quote_path='quotes/tdxQuote.txt'):
    # Read the quote file
    with open(quote_path, 'rb') as f:
        quote_data = f.read()
    
    # Create request
    request = {
        'quote': list(quote_data)  # Convert bytes to list for JSON serialization
    }
    
    # Serialize request
    request_json = json.dumps(request).encode()
    
    # Connect and send
    with socket.create_connection((host, port)) as sock:
        # Send length
        sock.send(struct.pack('>I', len(request_json)))
        # Send data
        sock.send(request_json)
        
        # Read response length
        resp_len = struct.unpack('>I', sock.recv(4))[0]
        # Read response
        response = sock.recv(resp_len)
        
        # Parse and print response
        resp_data = json.loads(response)
        print(f"Received encrypted key: {bytes(resp_data['encrypted_key']).hex()}")

if __name__ == '__main__':
    quote_path = sys.argv[1] if len(sys.argv) > 1 else 'quotes/tdxQuote.txt'
    send_quote(quote_path=quote_path)
