import rsa
import os
import base64
path_dir = 'S:/andrey/dieplom/client'

#pub = os.path.join(path_dir, 'pub_blockchain.txt')
#file = os.path.join(path_dir, 'file_blockchain.txt')

#pub = os.path.join(path_dir, 'pub.pem')
pub = os.path.join(path_dir, 'temp_pubkey_123.pem')
file = os.path.join(path_dir, '123.txt')
pub_key = '' 
with open(pub, 'r') as f:
	pub_key_pem = f.read()
	pub_key = rsa.PublicKey.load_pkcs1(pub_key_pem)

with open(file, 'r+') as f:
	data = f.read()
	data = data.encode('utf8')
	data = rsa.encrypt(data, pub_key)
print(pub_key)
with open(file, 'rb+') as f:
	f.write(data)
	

	