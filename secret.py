import etcd
import json
import argparse
import string
from ConfigParser import SafeConfigParser
from Crypto.Cipher import AES
import base64
import sys


LEN16 = 16
LEN24 = 24
LEN32 = 32

conf_file = SafeConfigParser()
conf_file.read("/etc/hpedockerplugin/hpe.conf")
CONF = conf_file.defaults()

if len(CONF) == 0:
    print("please Check the hpe.conf file on /etc/hpedockerplugin/ path")
    sys.exit(-1)



host_etcd_ip_address = CONF.get('host_etcd_ip_address'
host_etcd_port_number = int(CONF.get('host_etcd_port_number'))
host_etcd_client_cert = CONF.get('host_etcd_client_cert')
host_etcd_client_key = CONF.get('host_etcd_client_key')

if host_etcd_ip_address == None or host_etcd_port_number == None:
    print("Please check hpe.conf for host_etcd_ip_address or host_etcd_port_number")
    sys.exit(-1)



parser = argparse.ArgumentParser(description='Encryption Tool'
                                 ,usage='python secret.py [OPTIONS]')

parser.add_argument ("-key"
                     ,type=str,help="Key for Encryption")

parser.add_argument("-secret"
                    ,type=str,help="Text to Encrypt")

args = parser.parse_args()


def encrypt(message, passphrase):
    # passphrase MUST be 16, 24 or 32 bytes long, how can I do that ?
    aes = AES.new(passphrase, AES.MODE_CFB, '1234567812345678')
    return base64.b64encode(aes.encrypt(message))

def decrypt(encrypted, passphrase):
    aes = AES.new(passphrase, AES.MODE_CFB, '1234567812345678')
    return aes.decrypt(base64.b64decode(encrypted))


def key_check(key):
    KEY_LEN = len(key)
    padding_string = string.ascii_letters

    if KEY_LEN < LEN16:
        KEY = key + padding_string[:LEN16 - KEY_LEN]

    elif KEY_LEN > LEN16 and KEY_LEN < LEN24:
        KEY = key + padding_string[:LEN24 - KEY_LEN]

    elif KEY_LEN > LEN24 and KEY_LEN < LEN32:
        KEY = key + padding_string[:LEN32 - KEY_LEN]

    elif KEY_LEN > LEN32:
        KEY = key[:LEN32]

    return KEY

KEY = key_check(args.key)
SECRET = args.secret
MD = encrypt(SECRET, KEY)

class EtcdUtil(object):


    def __init__(self, host, port, client_cert, client_key):
        self.host = host
        self.port = port
        self.client_cert = client_cert
        self.client_key = client_key

        if client_cert is not None and client_key is not None:
            self.client = etcd.Client(host=host, port=port, protocol='https',
                                      cert=(client_cert, client_key))

        else:
            self.client = etcd.Client(host, port)

    def set_key(self,key, password):
        self.client.write(key,password)

    def get_key(self ,key):
        result = self.client.read(key)
        return result.value

cl = EtcdUtil(host_etcd_ip_address
             ,host_etcd_port_number
             ,host_etcd_client_cert
             ,host_etcd_client_key)

cl.set_key('KEY',MD)
CI = cl.get_key('KEY')

print(decrypt(CI,KEY))

