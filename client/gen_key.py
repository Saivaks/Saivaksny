import rsa
import os

path_dir = 'S:/andrey/dieplom/client'

priv = os.path.join(path_dir, 'privat.pem')
pub = os.path.join(path_dir, 'pub.pem')

(pubkey, privkey) = rsa.newkeys(512)
pubkey = rsa.PublicKey.save_pkcs1(pubkey, format='PEM')
privkey = rsa.PrivateKey.save_pkcs1(privkey, format='PEM')

with open(priv, 'wb') as file:
	file.write(privkey)
with open(pub, 'wb') as file:
	file.write(pubkey)
