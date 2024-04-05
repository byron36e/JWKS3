#Brian Erhart CSCE 3550
#Used code from main.py in the project1 folder provided. 
#Again, we've never been taught or shown how to do this kind of stuff, so I don't get how you expect us to do this. I asked for help for running the test client against my code and none of the TA's offered any real help. So i'm not sure how or if that works..

from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from urllib.parse import urlparse, parse_qs
from cryptography.fernet import Fernet
import os
import base64
import json
import jwt
import datetime
import sqlite3
import requests

#Sets up connection to sqlite and opens a db file
conn = sqlite3.connect('database.db')
cursor = conn.cursor()

hostName = "localhost"
serverPort = 8080

key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
os.environ['NOT_MY_KEY'] = key

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
expired_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)
expired_pem = expired_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

numbers = private_key.private_numbers()

key =  os.environ.get('NOT_MY_KEY')
 
if key: 
    cipher = Fernet(key.encode())

    encrypted_private_key = cipher.encrypt(private_key.encode())
    decrypted_private_key = cipher.decrypt(private_key.decode())


def int_to_base64(value):
    """Convert an integer to a Base64URL-encoded string"""
    value_hex = format(value, 'x')
    # Ensure even length
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')


class MyServer(BaseHTTPRequestHandler):   
    def do_PUT(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_PATCH(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_DELETE(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_HEAD(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_POST(self):
        parsed_path = urlparse(self.path)
        if parsed_irl.path == '/auth':
            content_length = int(self.headers['Content-Length']) 
            post_data = self.rfile.read(content_length).decode('utf-8') 
            data = json.loads(post_data) 
            name = data['name']
            email = data['email'] 
            db_cursor.execute('INSERT INTO users (name, email) VALUES (?, ?)', (name, email)) 
            db_conn.commit() 
            self.send_response(200) 
            self.send_header('Content-type', 'application/json') 
            self.end_headers() 
            response = { 
                'message': 'User created successfully', 
                'name': name, 
                'email': email 
                } 
            self.wfile.write(json.dumps(response).encode('utf-8')) 
        else: 
            self.send_response(404) 
            self.end_headers() 
            return

    def do_GET(self):
        parsed_url = urlparse(self.path) 
        if parsed_url.path == '/.well-known/jwks.json': 
            db_cursor.execute('SELECT * FROM users') 
            users = db_cursor.fetchall() 
            jwks = [] 
            for user in users: 
                jwks.append({ 
                    'name': user[0], 
                    'email': user[1] }) 
                self.send_response(200) 
                self.send_header('Content-type', 'application/json') 
                self.end_headers() 
                response = { 
                    'keys': jwks } 
                self.wfile.write(json.dumps(response).encode('utf-8')) 
        else: 
                self.send_response(404) 
                self.end_headers() 
                return
#adds a table then inserts the private keys generated
cursor.execute('''CREATE TABLE IF NOT EXISTS keys
               (id INTEGER PRIMARY KEY,
               private_key TEXT)''')

cursor.execute('INSERT INTO keys (private_key)VALUES (?)',(pem.decode('utf-8'),))
cursor.execute('INSERT INTO keys (private_key)VALUES (?)',(expired_pem.decode('utf-8'),))


if __name__ == "__main__":
    webServer = HTTPServer((hostName, serverPort), MyServer)
    print("Server started http;//%s:%s" %(hostName, serverPort))
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
    print("Server closed.")
#commits and closes the database
conn.commit()
conn.close()
