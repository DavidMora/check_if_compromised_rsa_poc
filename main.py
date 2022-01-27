from cryptography.hazmat.primitives.asymmetric import rsa
from Crypto.PublicKey import RSA
import OpenSSL
import ssl
import requests
from termcolor import colored

FACTORDB_ENDPOINT = "http://factordb.com/api"

def connect(n):
    result = requests.get(FACTORDB_ENDPOINT , params={"query": str(n)})
    return result

def is_vulnerable(n):
    '''
    This indicates how the number is currently listed in the database.
    C   Composite, no factors known
    CF  Composite, factors known
    FF  Composite, fully factored
    P   Definitely prime
    Prp Probably prime
    U   Unknown
    Unit    Just for "1"
    N   This number is not in database (and was not added due to your settings)
    *   Added to database during this request
    '''

    result = connect(n)
    status = result.json().get('status')
    return status != 'C'

if __name__ == '__main__':
    cert = ssl.get_server_certificate(('PUT_YOUR_HOST_NAME_HERE', 443))
    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
    pk = x509.get_pubkey()
    pem = OpenSSL.crypto.dump_publickey(OpenSSL.crypto.FILETYPE_PEM, pk)
    public_key = RSA.importKey(pem)
    if is_vulnerable(public_key.n):
        print(colored("CERTIFICATE HAS BEEN FACTORED --- CHANGE CERTIFICATE IMMEDIATELLY", 'red'))
    else:
        print(colored("CERTIFICATE IS SAFE SO FAR, BUT YOU SHOULDN'T BE USING RSA ANY WAY", 'green'))
    
