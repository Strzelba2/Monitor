import os

TEST_PATH = os.getcwd()
BASE_DIR = os.path.dirname(TEST_PATH)

env_file_path = os.path.join(BASE_DIR,".env")

HTTP_URL_LOGIN = "http://127.0.0.1:8000/login/"
HTTPS_URL_LOGIN = "https://SessionID:8080/login/"
HTTPS_URL_LOGOUT = "https://SessionID:8080/logout/"
HTTPS_URL_REFRESH = "https://SessionID:8080/refresh/"
HTTPS_WRONG_HOST_URL = "https://127.0.0.1:8080/login/"
LOKI_URL = 'http://127.0.0.1:3100/loki/api/v1/push'

secret_timeout = 2

client_id = 'test_id'
username = 'testUserApache'
password = 'test!pass@.word2D'
lastname = 'testlastname'
firstname = 'testfirstname'
email = 'testfirst@email.com'
client_secret='test_secret'
hashed_secret = ''

wrong_user = "Czesław"
wrong_pass = "Czesław21"

stream_labels_secret = {"job": "secret_provider", "instance": "secret-instance-1"}

SERVER_FILE =os.path.join(BASE_DIR,"cert","new","server.crt") 
SERVER_KEY_FILE = os.path.join(BASE_DIR,"cert","new","server.key") 
SERVER_CA_FILE = os.path.join(BASE_DIR,"cert","new","combined_ca.crt") 

CERT_FILE =os.path.join(BASE_DIR,"cert","new","client.crt") 
KEY_FILE = os.path.join(BASE_DIR,"cert","new","client.key") 
CA_FILE = os.path.join(BASE_DIR,"cert","new","ca.crt") 

CA_KEY_FILE = os.path.join(BASE_DIR,"cert","new","ca.key")
CONF_CERT_FILE = os.path.join(BASE_DIR,"cert","new","client_cert.cnf") 
CSR_CERT_FILE = os.path.join(BASE_DIR,"cert","new","client.csr")

ADMIN_CERT_FILE =os.path.join(BASE_DIR,"cert","new","admin_client.crt") 
ADMIN_KEY_FILE = os.path.join(BASE_DIR,"cert","new","admin_client.key") 

WRONG_CERT_FILE =os.path.join(BASE_DIR,"cert","new","wrong_client.crt") 

DOCKER_CLIENT_CERT = "/sessionServer/cert/new/client.crt"

headers = {
    'X-Forwarded-For': '203.0.113.195',
    "Content-Type": "application/json",
    "Accept": "application/json"
}

