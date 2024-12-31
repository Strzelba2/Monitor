#!/usr/bin/env python3

import os
import json
import ssl
import multiprocessing
import http.server
import requests
import time
import logging
from constants import *

# Path for the log file
log_file_path = 'secret.log'

# Logger setup
logger = logging.getLogger("test_secret")
logger.setLevel(logging.DEBUG)

file_handler = logging.FileHandler("secret.log")  
file_handler.setLevel(logging.DEBUG)

# Create a formatter and set it for the handler
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)

logger.addHandler(file_handler)

def push_log_to_loki(log_message: str, stream_labels: dict) -> None:
    """
    Push a log message to Loki.

    Args:
        log_message (str): The log message to send.
        stream_labels (dict): Labels for the Loki stream.
    """
    log_entry = {
        "streams": [
            {
                "stream": stream_labels,
                "values": [
                    [str(int(time.time() * 1e9)), log_message] 
                ]
            }
        ]
    }

    headers = {'Content-Type': 'application/json'}
    try:
        response = requests.post(LOKI_URL, headers=headers, data=json.dumps(log_entry))
        logger.debug(f"Log successfully pushed to Loki:")
    except requests.exceptions.RequestException as e:
        logger.error(f"Error pushing log to Loki: {str(e)}")


class TLS_PROTOCOL(dict):
    highest = ssl.PROTOCOL_TLS
    TLSv1_2 = ssl.PROTOCOL_TLSv1_2
    TLSv1_1 = ssl.PROTOCOL_TLSv1_1
    TLSv1_0 = ssl.PROTOCOL_TLSv1
    
class TLS_PROTOCOL_available(dict):
    highest = ssl.HAS_TLSv1_3
    TLSv1_2 = ssl.HAS_TLSv1_2
    TLSv1_1 = ssl.HAS_TLSv1_1
    TLSv1_0 = ssl.HAS_TLSv1
    
class SecretServer(http.server.HTTPServer):
    def __init__(self, address: tuple, handler: http.server.BaseHTTPRequestHandler):
        """
        HTTP server for handling secret-related requests.
        """
        super().__init__(address, handler)
        
        
class MySSLSocket (ssl.SSLSocket):
    def accept(self, *args, **kwargs):
        logger.debug('Accepting connection...')
        push_log_to_loki('Accepting connection...',stream_labels_secret)
        result = super(MySSLSocket, self).accept(*args, **kwargs)
        logger.debug('Done accepting connection.')
        push_log_to_loki('Done accepting connection.',stream_labels_secret)
        
        return result

    def do_handshake(self, *args, **kwargs):
        push_log_to_loki('Starting handshake...',stream_labels_secret) 
        logger.debug('Starting handshake...')   
        result = super(MySSLSocket, self).do_handshake(*args, **kwargs)
        logger.debug('Done with handshake.') 
        push_log_to_loki('Done with handshake.',stream_labels_secret)  
        cipher , TLS , bit = self.cipher()
        SecretHandler.cipher = cipher
        SecretHandler.TLS = TLS
        logger.debug(f'Done with handshake. result:  {result}') 
        push_log_to_loki(f'Done with handshake. result:  {result}',stream_labels_secret) 

        return result
    
class MySSLContext(ssl.SSLContext):
    def wrap_socket(self, sock, server_side=False,
                    do_handshake_on_connect=True,
                    suppress_ragged_eofs=True,
                    server_hostname=None, session=None) -> MySSLSocket:
        """
        Wrap a socket with SSL context using MySSLSocket for logging.
        """
        return MySSLSocket._create(
            sock=sock,
            server_side=server_side,
            do_handshake_on_connect=do_handshake_on_connect,
            suppress_ragged_eofs=suppress_ragged_eofs,
            server_hostname=server_hostname,
            context=self,
            session=session
        )


class SecretProvider(multiprocessing.Process):
        
    def __init__(self, server_port: int, hashed_secret: str):
        """
        Initialize the SecretProvider process.
        """
        self.clean_logs()
        logger.debug("__init__ ")
        
        self.server_port = server_port
        self.hashed_secret = hashed_secret
        logger.debug(f"self.hashed_secret  __init__:   {self.hashed_secret}")
        super().__init__()
        

    def run(self):
        """
        Run the SecretProvider HTTP server with SSL.
        """
        logger.debug("Starting SecretProvider HTTP Server ")
        push_log_to_loki("Starting SecretProvider HTTP Server",stream_labels_secret)

        self.http_handler = SecretServer(
                    ('localhost', self.server_port),
                    lambda *args, **kwargs: SecretHandler(*args, hashed_secret=self.hashed_secret, **kwargs))
        
        context = MySSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=SERVER_FILE, keyfile=SERVER_KEY_FILE)
        context.load_verify_locations(cafile=SERVER_CA_FILE)
        context.verify_mode = ssl.CERT_REQUIRED
        self.http_handler.socket = context.wrap_socket(self.http_handler.socket, server_side=True)
        self.http_handler.serve_forever()

    def clean_logs(self):
        """
        Clean the log file by truncating it.
        """
        if os.path.exists(log_file_path):
            open(log_file_path, 'w').close() 
            logger.info("Log file cleaned successfully.")

    def stop(self):
        """
        Stop the SecretProvider HTTP server.
        """
        logger.debug("Shutting down SecretProvider HTTP Server")
        self.http_handler.shutdown()
        self.http_handler.server_close()


class SecretHandler(http.server.BaseHTTPRequestHandler):
    def __init__(self, *args, hashed_secret=None, **kwargs):
        """
        HTTP handler for managing secret-related requests.
        """
        self.hashed_secret = hashed_secret 
        print("secretprovider success")
        super().__init__(*args, **kwargs)
        
    def do_GET(self):
        """
        Handle GET requests for health checks.
        """
        logger.debug("Secret Provider GET")
        if self.path == '/health':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"status": "ok"}).encode('utf-8'))
        else:
            self.send_response(404)
            self.end_headers()
    
    def do_POST(self):
        """
        Handle POST requests for verifying secrets.
        """
        if self.path == '/verify_and_return_secret/':
            push_log_to_loki("Secret Provider POST",stream_labels_secret)
            logger.debug("Secret Provider POST")

            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            data = json.loads(post_data.decode('utf-8'))
            logger.debug(f"Received data: {data}")

            req_username = data.get('username')
            req_hashed_secret = data.get('hashed_secret')

            if req_username == username and req_hashed_secret == self.hashed_secret:
                response = {'secret': client_secret}
                time.sleep(1)
                logger.debug("Valid credentials")
                push_log_to_loki("Valid credentials",stream_labels_secret)
                
                self.send_response(200)
            else:
                logger.debug('Invalid credentials')
                response = {'error': 'Invalid credentials'}
                self.send_response(401)

            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(response).encode('utf-8'))
        else:
            self.send_response(404)
            self.end_headers()
            
if __name__ == '__main__':
    logger.debug('SecretProvider__main__') 
    config_handler = SecretProvider(9876,'test_secret')
    config_handler.start()
