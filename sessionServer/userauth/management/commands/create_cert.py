from django.core.management.base import BaseCommand
from django.conf import settings
import subprocess
import os
import logging

logger = logging.getLogger('django')

class Command(BaseCommand):
    help = 'Initialize or update the allowed users file with existing usernames in the database.'
    def add_arguments(self, parser):
        parser.add_argument('username', type=str, help='Username for the client_secret retrieval')
    
    def handle(self, *args,**options):
        os.environ['LANG'] = 'en_US.UTF-8'
        os.environ['LC_CTYPE'] = 'UTF-8'
        
        username = options['username']
        
        with open(settings.CONF_CERT_FILE, 'r', encoding='utf-8') as configfile:
            lines = configfile.readlines()
            
        section_found = False

        for i in range(len(lines)):
            line = lines[i].strip()

            if line == '[ req_distinguished_name ]':
                section_found = True
        
            if section_found and line.startswith('commonName_default'):
                lines[i] = f'commonName_default         = {username}\n'
                break  

        if not section_found:
            raise ValueError("Can not finde [ req_distinguished_name ] section in cnf file")

        with open(settings.CONF_CERT_FILE, 'w', encoding='utf-8') as configfile:
            configfile.writelines(lines)
            
        try:
            subprocess.run(
                [
                    "openssl", "req",
                    "-new",
                    "-key", settings.SECRET_KEY_PATH,
                    "-out", settings.CSR_CERT_FILE,
                    "-config", settings.CONF_CERT_FILE,
                    "-batch",
                ],
                check=True
            )

        except subprocess.CalledProcessError as e:
            print("Error generating certificate:", e)
            
        try:
            subprocess.run(
                [
                    "openssl", "x509", "-req", "-days", "365",
                    "-in", settings.CSR_CERT_FILE,
                    "-CA", settings.CA_CERT_PATH ,
                    "-CAkey", settings.CA_KEY_FILE,
                    "-CAcreateserial",  
                    "-out", settings.SECRET_CERT_PATH,
                    "-extfile", settings.CONF_CERT_FILE, "-extensions", "req_ext"
                ],
                check=True
            )
            print(f"CA Signed Certificate generated at {settings.SECRET_CERT_PATH}")
        except subprocess.CalledProcessError as e:
            print("Error generating certificate:", e)
            
        self.stdout.write(self.style.SUCCESS(
            f'certificate for the user {username} was created correctly.'
        ))
