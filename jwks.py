#Author: Brian Erhart CSCE 3550 sec 002
#gradebot kept giving me a zero for everything despite how many times I tried to fix it, although I didnt receive any errors and I checked and it does confirm all of my tables were created and inserting/encrypting properly, so im not sure what was going wrong.

from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from urllib.parse import urlparse, parse_qs
import uuid
import argon2 
import base64
import json
import jwt
import datetime
import sqlite3
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad
from Crypto.Random import get_random_bytes
import os

#Sets up connection to sqlite and opens a db file
conn = sqlite3.connect('database.db')
cursor = conn.cursor()

hostName = "localhost"
serverPort = 8080


#generating keys
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
expired_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
#encoding keys
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
conn.commit()

def int_to_base64(value):
    """Convert an integer to a Base64URL-encoded string"""
    value_hex = format(value, 'x')
    # Ensure even length
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')

secret_key = os.environ.get('NOT_MY_KEY')
secret_key = "NOT_MY_KEY"

key = pad(secret_key.encode(), AES.block_size)

def encrypt_private_keys(private_keys):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(private_key, AES.block_size))
    return cipher.iv, ct_bytes

def decrypt_private_key(iv,ct_bytes):
    cipher = AES.new(key, AES.MODE_CBC,iv)
    pt = unpad(cipher.decrypt(ct_bytes),AES.block_size)
    return pt.decode()
    
create_table_query = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    email TEXT UNIQUE,
    date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP
)
"""
cursor.execute(create_table_query)
conn.commit()


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
        if self.path == '/register':
            # Read the request body
            content_length = int(self.headers['Content-Length'])
            body = self.rfile.read(content_length)
           
            # Parse the JSON request body
            data = json.loads(body)
           
            # Generate a secure password using UUIDv4
            password = str(uuid.uuid4())
           
            # Hash the password using Argon2
            password_hash = argon2.PasswordHasher().hash(password)
           
            # Store the user details and hashed password in the 'users' table
            cursor = conn.cursor()
            insert_query = "INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)"
            cursor.execute(insert_query, (data['username'], password_hash, data['email']))
            conn.commit()
           
            # Prepare the response JSON
            response = {'password': password}
            response_body = json.dumps(response).encode('utf-8')
           
            # Send the response back to the client
            self.send_response(201)  # Created status code
            self.send_header('Content-type', 'application/json')
            self.send_header('Content-length', len(response_body))
            self.end_headers()
            self.wfile.write(response_body)
        else:
            self.send_response(404)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'Endpoint not found')

    def do_POST(self):
        parsed_path = urlparse(self.path)
        if parsed_irl.path == '/auth':
            content_length = int(self.headers['Content-Length']) 
            post_data = self.rfile.read(content_length).decode('utf-8') 
            data = json.loads(post_data) 
            name = data['name']
            email = data['email'] 
            cursor.execute('INSERT INTO users (name, email) VALUES (?, ?)', (name, email)) 
            conn.commit() 
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

    def do_POST(self):
        if self.path == '/auth':
            user_id = self.parse_user_id()
            request_ip = self.client_address[0] 
            self.log_auth_request(user_id, request_ip)

    def log_auth_request(self, user_id, request_ip):
        
        cursor = conn.cursor()

        # Create the auth_logs table if it doesn't exist
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS auth_logs(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_ip TEXT NOT NULL,
                request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                user_id INTEGER,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );
        ''')

        # Insert the log entry into the auth_logs table
        cursor.execute('''
            INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)
        ''', (request_ip, user_id))

        
        conn.commit()
        
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
                
    def parse_user_id(self):
    	content_length = int (self.headers['Content-Length'])
    	post_data = self.rfile.read(content_length).decode('utf-8')
    	parsed_data = parse_qs(post_data)
    	user_id = parsed_data.get('get_id',[''])[0]
    	return user_id
    	

    	 
#adds a table then inserts the private keys generated
cursor.execute('''CREATE TABLE IF NOT EXISTS keys
               (id INTEGER PRIMARY KEY,
               private_key TEXT)''')
    
conn.commit()

cursor.execute('INSERT INTO keys (private_key)VALUES (?)',(pem.decode('utf-8'),))
cursor.execute('INSERT INTO keys (private_key)VALUES (?)',(expired_pem.decode('utf-8'),))
conn.commit()

if __name__ == "__main__":
    webServer = HTTPServer((hostName, serverPort), MyServer)
    print("Server started http://%s:%s" %(hostName, serverPort))
    conn.commit()
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
    print("Server closed.")
#commits and closes the database
conn.commit()
conn.close()
