import rsa
import os

path_dir = 'S:/andrey/dieplom/client'

priv = os.path.join(path_dir, 'privat.pem')
pub = os.path.join(path_dir, 'pub.pem')

with open(pub, 'r') as f:
	pub_key_pem = f.read()
	pub_key = rsa.PublicKey.load_pkcs1(pub_key_pem)

with open(priv, 'rb') as f:
	priv_key_pem = f.read()
	priv_key = rsa.PrivateKey.load_pkcs1(priv_key_pem)
test='123'
test1='1231'
test = rsa.encrypt(test.encode('utf8'), pub_key)
test = test.decode('utf8')
test = test.encode('utf8')
test = rsa.decrypt(test, priv_key)
print(test.decode('utf8'))

signature = rsa.sign(test.encode('utf8'), priv_key, 'SHA-1')
rsa.verify(test1.encode('utf8'), signature, pub_key)