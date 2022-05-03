import rsa
import os
import base64
path_dir = 'S:/andrey/dieplom/client'

#file = os.path.join(path_dir, 'file_blockchain.txt')

priv = os.path.join(path_dir, 'privat.pem')
file = os.path.join(path_dir, 'res_123.txt')
#file = os.path.join(path_dir, '123.txt')
priv_key = '' 
with open(priv, 'r') as f:
	priv_key_pem = f.read()
	priv_key = rsa.PrivateKey.load_pkcs1(priv_key_pem)

with open(file, 'rb') as f:
	data = f.read()
	data = rsa.decrypt(data, priv_key)
	data = data.decode('utf8')
with open(file, 'w+') as f:
	f.write(data)