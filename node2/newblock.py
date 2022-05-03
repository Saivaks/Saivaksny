import hashlib
import json
import os
import sys
import rsa
import requests
from base64 import b64encode
from base64 import b64decode
from hashlib import sha256
from time import time
from uuid import uuid4
from flask import Flask, request, redirect, url_for
from werkzeug.utils import secure_filename
from flask import Flask, jsonify, request
from flask import send_file

class Blockchain:
	def __init__(self):
		if type_node =='FO':
			# В этом свойстве будут содержаться все блоки.
			self.chain = [{
				'hash_transaction':None,
				'index': 1,
				'previous_hash': 123,
				'proof': None,
				'timestamp': time(),
				'transaction': None,
			}]
			new_config = {'client': [],'FOA':[], 'FO':[]}
			self.init_node(new_config)
			#self.chain = self.chain.append(self.new_block(None,None,None,123))
			
		elif type_node =='FOA':
			
			response = requests.get('http://'+ initializing_node + '/service/synchronization')
			
			values = response.json()
			self.update_Blockchain(values)
			self.init_node(values['config'])
			self.synchronization_all()
				
	def init_node(self, old_data):
		self.init_config(old_data)
		pubkey = self.init_key()
		self.write_config(type_node, node_identifier, addres_node, 'computer', pubkey)
		self.smart_contract('', node_identifier, node_identifier, path_config, '', 'change_config', 0)

	def init_key(self):
		(pubkey, privkey) = rsa.newkeys(512)
		privkey = rsa.PrivateKey.save_pkcs1(privkey, format='PEM')
		pubkey = rsa.PublicKey.save_pkcs1(pubkey, format='PEM')
		with open(priv, 'wb') as file:
			file.write(privkey)
		return pubkey

	def init_config(self, old_data):
		with open(path_config, 'w') as file:
			json.dump(old_data, file)

	def update_Blockchain(self, values):
		self.chain = values['chain'].copy()
		if not self.valid_chain():
			print('not valid')
			
		if self.chain[self.len_Blockchain()-1]['transaction']['type_operation'] == 'change_config':
			
			self.init_config(values['config'])
		

	def synchronization_all(self):
		with open(path_config, "r") as file:
			data_config = json.load(file)
		if not self.valid_chain():
			print('not valid1')
		
		new_data = {'chain':self.chain, 'config':data_config}
		#print('new')
		#print(new_data)
		for node in range (len(data_config['FO'])):
			
			if (data_config['FO'][node]['addres_device'] != addres_node):
				#print('123')
				
				requests.post('http://' + data_config['FO'][node]['addres_device'] + '/service/synchronization_all', json = new_data)

		for node in range (len(data_config['FOA'])):
			
			if (data_config['FOA'][node]['addres_device'] != addres_node):
				requests.post('http://' + data_config['FOA'][node]['addres_device'] + '/service/synchronization_all', json = new_data)
		

	def write_config(self, type_node, id_device, addres_device, type_device, pubkey):
		with open(path_config, "r") as file:
			data = json.load(file)
		data[type_node].append({'id_device':id_device, 'addres_device':addres_device, 'type_device':type_device, 'pubkey':pubkey.decode("utf-8")})
		with open(path_config, 'w+') as file:
			json.dump(data, file)

	def get_Last_Block(self):
		return self.chain[len(self.chain) - 1]
	def len_Blockchain(self):
		return len(self.chain)
	def add_block (self, block):
		self.chain.append(block)
	@staticmethod
	def hash(block):
		hash = sha256()
		hash.update(str(block).encode('utf-8'))
		return hash.hexdigest()

	@staticmethod
	def hash_file(path):
		hash = sha256()
		with open(path, 'rb') as file:
			while True:
				data = file.read(BUF_SIZE)
				if not data:
					break
				hash.update(data)
		return hash.hexdigest()

	@staticmethod
	def decrypt_file(sender, recipient, path_send_file, type_operation):
		if type_operation == 'request':
			priv_name = 'temp_privkey_' + sender + '.pem'
		else:
			priv_name = 'privat.pem'

		priv_file = os.path.join(path_file, priv_name)
		
		with open(priv_file, 'r') as f:
			priv_key_pem = f.read()
			priv_key = rsa.PrivateKey.load_pkcs1(priv_key_pem)
		
		with open(path_send_file, 'rb') as f:
			data = f.read()
			
			data = rsa.decrypt(data, priv_key)
			data = data.decode('utf8')
		if type_operation =='processing':
			path_send_file = recipient + '.txt'
			path_send_file = os.path.join(path_file, path_send_file)
			
		with open(path_send_file, 'w+') as f:
			f.write(data)
		return path_send_file
	@staticmethod
	def encrypt_file(recipient, path_send_file, type_operation, filename = None):
		with open(path_config, "r") as read_file:
			data = json.load(read_file)
		
		for key in list(data.keys()):
			for node in range (len(data[key])):
				if (data[key][node]['id_device'] == recipient):
					pub_key = rsa.PublicKey.load_pkcs1(data[key][node]['pubkey'].encode('utf8'))
					break
		if type_operation == 'processing':
			path_send_file = recipient + '.txt'
			path_send_file = os.path.join(path_file, path_send_file)
			
		with open(path_send_file, 'r+') as f:
			data = f.read()
			data = data.encode('utf8')
			data = rsa.encrypt(data, pub_key)
		with open(path_send_file, 'rb+') as f:
			print(path_send_file)
			f.write(data)
		if type_operation == 'save':
			print('FAFASF')
			path_send_file = os.path.join(path_file, filename)
			print(path_send_file)
		with open(path_send_file, 'rb+') as f:
			f.write(data)
	def get_pubkey(self, path_file):
		with open(path_file, 'r') as file:
			pub_key_pem = file.read()
			pub_key = rsa.PublicKey.load_pkcs1(pub_key_pem)
		data = rsa.PublicKey.save_pkcs1(pub_key, format='PEM')#.decode('utf8')
		return data

	
	

	def new_transaction( self, client, sender, recipient, hash_data, name_data, type_operation, pivo):
		"""
		Направляет новую транзакцию в следующий блок
		:param client: <str> Адрес клиента
		:param recipient: <str> Адрес назначенного узла
		:param sender: <str> Адрес узла обработавшего транзакцию
		:param hash_data: <str> Хэш данных
		:param type_operation: <int> Тип операции
		:param pivo: <int> Награда
		:return: <int> Индекс блока, который будет хранить эту транзакцию
		"""
		self.current_transactions={
			'client':client,
			'sender': sender,
			'recipient': recipient,
			'hash_data':hash_data,
			'name_data':name_data,
			'type_operation':type_operation,
			'pivo': pivo,
		}
		return self.current_transactions
	def new_block(self, transaction, proof, hash_transaction, previous_hash=None):
		# Так как мы добавляем новый блок, prevHash будет хешем предыдущего последнего блока.
		block = {
			'index': self.len_Blockchain() + 1,
			'timestamp': time(),
			'transaction': self.current_transactions,
			'proof': proof,
			'hash_transaction':hash_transaction,
			'previous_hash': previous_hash or self.hash(self.chain[-1]),
		}
		return block

	def temp_key(self, id_client):
		(pubkey, privkey) = rsa.newkeys(512)
		privkey = rsa.PrivateKey.save_pkcs1(privkey, format='PEM')
		pubkey = rsa.PublicKey.save_pkcs1(pubkey, format='PEM')
		pub_name = 'temp_pubkey_' + str(id_client) + '.pem'
		pub_filename = os.path.join(path_file, pub_name)
		priv_name = 'temp_privkey_' + str(id_client) + '.pem'
		priv_filename = os.path.join(path_file, priv_name)
		with open(pub_filename, 'wb+') as file:
			file.write(pubkey)
		with open(priv_filename, 'wb+') as file:
			file.write(privkey)
		return pub_filename

	def check_reg(self, client, type_usr):
		with open(path_config, 'r+') as file:
			data = json.load(file)

		for i in data[type_usr]:
			if i['id_device'] == client:
				return True
		return False

	def check_config(self):
		#with open(path_config, 'r') as file:
		#	data = json.load(file)
		hash_data = self.hash_file(path_config)
		for i in  reversed (range (1, self.len_Blockchain())):
			if (self.chain[i]['transaction']['type_operation'] == 'change_config'):
				#добавить имя файла в транзакцию
				if (self.chain[i]['transaction']['hash_data'] == hash_data):
					return True
				else:
					return False

	def valid_chain(self):
		
		for i in range (1, self.len_Blockchain()):
			
			current_Block = self.chain[i]
			previous_Block = self.chain[i - 1]
			
			if (current_Block['previous_hash'] != self.hash(previous_Block)):
				return False
		return True

	def registration_user(self, id_user, pubkey):
		self.write_config('client', id_user, 'computer', '', pubkey)
		self.smart_contract(id_user, id_user, node_identifier, path_config, '','change_config', 0)

	def get_file(self, id_user, file_name):
		result = ''
		id_device = ''
		addres_device = ''
		path = os.path.join(path_file, file_name)
		for i in  reversed (range (1, self.len_Blockchain())):
			if (self.chain[i]['transaction']['client'] == id_user):
				
				if (self.chain[i]['transaction']['name_data'] == file_name):
					if (self.chain[i]['transaction']['type_operation'] == 'save'):
						if (self.chain[i]['transaction']['sender'] == node_identifier):
							if (self.chain[i]['transaction']['hash_data'] == self.hash_file(path)):
								result = 'ok'
								break
							else:
								result = 'Данные поврежденны'
								print(result)
						else:
							if result!='ok':
								result = 'not this device'
								id_device = self.chain[i]['transaction']['sender']
							
					#else:
					#	if result!='ok':
					#		result = 'data not ready'
						
		if (result == ''):
			result = 'transaction not find'
		if id_device != '' and result!= 'ok':
			with open(path_config, "r") as read_file:
				data = json.load(read_file)
			for node in range (len(data['FOA'])):
				if (data['FOA'][node]['id_device'] == id_device):
					addres_device = data['FOA'][node]['addres_device']
		print(result)
		print(addres_device)
		return result, addres_device

	def create_signature(self, transaction):
		key_file = os.path.join(path_file, 'privat.pem')
		with open(key_file, 'r') as file:
			priv_key_pem = file.read()
			priv_key = rsa.PrivateKey.load_pkcs1(priv_key_pem)
		hash = sha256()
		hash.update(json.dumps(transaction).encode('utf-8'))
		hash_transaction = hash.hexdigest()
		
		
		signature = rsa.sign(hash_transaction.encode('utf-8'), priv_key, 'SHA-1')
		signature_b64 = b64encode(signature)
		
		
		signature_string = signature_b64.decode('utf-8')
		

		data = {'id_device':node_identifier, 'hash_transaction':hash_transaction, 'signature':signature_string}
		return data

	def check_signature(self, id_device, hash_transaction, signature_string):
		with open(path_config, "r") as read_file:
			data = json.load(read_file)
		for key in list(data.keys()):
			for node in range (len(data[key])):
				if (data[key][node]['id_device'] == id_device):
					pubk = rsa.PublicKey.load_pkcs1(data[key][node]['pubkey'].encode('utf8'))
					break
		#try:
		
		signature_b64 = signature_string.encode('utf-8')
		
		signature = b64decode(signature_b64)
		
		rsa.verify(hash_transaction.encode('utf-8'), signature, pubk)
		return True

		#except:
			#return False

	def smart_contract (self, client, sender, recipient, path, filename, type_operation, price):
		# расшифровка файла
		print(type_operation)
		if type_operation != 'change_config':
			path_send_file = self.decrypt_file(sender, recipient, path, type_operation)
		if type_operation == 'save':
			self.encrypt_file(recipient, path, type_operation, filename)
		hash_data = self.hash_file(path)
		transaction = self.new_transaction(client, sender, recipient, hash_data, filename, type_operation, price)
		
		if transaction is not None:
			signature_info = self.create_signature(transaction)
			if type_node =='FOA' and client !='':
				response = requests.post('http://' + initializing_node + '/service/check_signature', json = signature_info)
				res = response.json()
				
				result = res['result_check']
				
			else:
				result = self.check_signature(signature_info['id_device'], signature_info['hash_transaction'], signature_info['signature'])
			if result == False:
				return "не получилось потвердить подпись узла. Обратитесь к другому"
			block = self.new_block(transaction, signature_info['signature'], signature_info['hash_transaction'])
		else:
			block = self.new_block(transaction, None, None)
		self.add_block(block)
		
		# зашифровка файла
		#if type_operation != 'change_config':
		#	self.encrypt_file(recipient, path)
		self.synchronization_all()
		with open(path_config, "r") as file:
			data_config = json.load(file)
		if type_operation == 'request':
			
			processing_info = {'client':client, 'sender':node_identifier, 'recipient':data_config['FO'][0]['id_device']}
			processing_data = {'file':open(path, "rb")}
			self.encrypt_file(processing_info['recipient'], path , type_operation)
			response = requests.post('http://' + initializing_node + '/transaction/dispatching', data = processing_info, files = processing_data)
			return "Заявка на услугу получена"
		if type_operation == 'dispatching':
			self.encrypt_file(node_identifier, path, type_operation)
		if type_operation == 'processing':
			processing_info = {'client':client, 'sender':node_identifier, 'recipient':recipient, 'filename':filename}
			processing_data = {'file':open(path_send_file, "rb")}
			
			self.encrypt_file(processing_info['recipient'], path, type_operation)
			with open(path_config, "r") as file:
				data_config = json.load(file)
			
			for node in range (len(data_config['FOA'])):
				if (data_config['FOA'][node]['id_device'] == recipient):
					print(data_config['FOA'][node]['addres_device'])
					requests.post('http://' + data_config['FOA'][node]['addres_device'] + '/transaction/processing', data = processing_info, files = processing_data)
					break
		if type_operation == 'save':
			#self.encrypt_file(recipient, path, type_operation, filename)
			return "задачи выполнены"
		return "Заявка на услугу получена и обработана"

# Создаем экземпляр узла
app = Flask(__name__)
with open('config_node.json', "r") as read_file:
	node_info = json.load(read_file)
path_user = node_info['path_user']
path_file = node_info['path_dir']
ip = node_info['ipv4']
port = node_info['port']
URL = 'http://' + ip + ':' + port
type_node = node_info['type_node']

addres_node = ip + ':' + port
initializing_node = node_info['initializing_node']

path_config = os.path.join(path_file, 'config.json')
priv = os.path.join(path_file, 'privat.pem')

BUF_SIZE = 262144
ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'])
app.config['UPLOAD_FOLDER'] = path_file
# Генерируем уникальный на глобальном уровне адрес для этого узла
node_identifier = str(uuid4()).replace('-', '')

# Создаем экземпляр блокчейна
blockchain = Blockchain()

@app.route('/transaction/new', methods=['GET','POST'])
def service_request():
	file = request.files['file']
	if 'file' not in request.files:
		return "Нет файла"
	if file.filename == '':
		return "Нет выбранного файла"
	filename = secure_filename(file.filename)
	file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
	file.save(file_path)
	#values = request.get_json()
	values = dict(request.form)
	# Убедитесь в том, что необходимые поля находятся среди POST-данных 
	required = ['client']
	if not all(k in values for k in required):
		return 'Missing values', 400
	if not blockchain.check_reg(values['client'], 'client'):
		return 'Не зарегестрированный пользователь'
	# Создание новой транзакции
	#index = blockchain.smart_contract(values['client'], values['client'], node_identifier, file_path, filename, values['type_operation'], 1)
	index = blockchain.smart_contract(values['client'], values['client'], node_identifier, file_path, filename, 'request', 1)
	response = {'message': f'{index}'}
	return jsonify(response), 201

@app.route('/transaction/dispatching', methods=['GET','POST'])
def dispatching():
	
	file = request.files['file']
	
	if 'file' not in request.files:
		return "Нет файла"
	if file.filename == '':
		return "Нет выбранного файла"
	filename = secure_filename(file.filename)
	file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
	file.save(file_path)
	#values = request.get_json()
	values = dict(request.form)
	
	# Убедитесь в том, что необходимые поля находятся среди POST-данных 
	required = ['client', 'sender', 'recipient']
	if not all(k in values for k in required):
		return 'Missing values', 400
	if not blockchain.check_reg(values['sender'], 'FOA'):
		return 'Не зарегестрированный узел'
	index = blockchain.smart_contract(values['client'], node_identifier, values['recipient'], file_path, filename, 'dispatching', 10)
	#идет диспечерезация
	with open(path_config, "r") as file:
		data_config = json.load(file)
	
	for node in range (len(data_config['FOA'])):
		
		index = blockchain.smart_contract(values['client'], node_identifier, data_config['FOA'][node]['id_device'], file_path, filename, 'processing', 10)
	return "Задачи назначены"


@app.route('/transaction/processing', methods=['GET','POST'])
def processing():
	
	file = request.files['file']
	if 'file' not in request.files:
		return "Нет файла"
	if file.filename == '':
		return "Нет выбранного файла"
	filename = secure_filename(file.filename)
	file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
	file.save(file_path)
	#values = request.get_json()
	values = dict(request.form)
	
	# Убедитесь в том, что необходимые поля находятся среди POST-данных 
	required = ['client', 'sender', 'recipient','filename']
	if not all(k in values for k in required):
		return 'Missing values', 400
	if not blockchain.check_reg(values['sender'], 'FO'):
		return 'Не зарегестрированный узел'
	#тут обработка данных
	index = blockchain.smart_contract(values['client'], node_identifier, values['client'], file_path, values['filename'], 'save', 10)
	return 'Задача Обработана'


@app.route('/request/get_file', methods=['GET','POST'])
def get_file():
	values = request.get_json()
	required = ['client', 'name_data']
	if not all(k in values for k in required):
		return 'Missing values', 400

	result, addres_device = blockchain.get_file(values['client'], values['name_data'])
	print(result)
	print(addres_device)
	if result == 'ok':
		full_path_file = os.path.join(path_file, values['name_data'])
		full_path_user = os.path.join(path_user, 'res_' + values['name_data'])
		#вынужденные операции т.к. копировать в потсмене заш. нельзя
		with open(full_path_file, 'rb') as file:
			data = file.read()
		with open(full_path_user, 'wb+') as file:
			file.write(data)

		return send_file(full_path_file)
	elif addres_device != '' and result!='ok':
		response  = requests.post('http://' + addres_device + '/request/get_file', json = values)
		print('ответ')
		print(response.content)
		return response.content
	else:
		return result



@app.route('/authentication/check', methods=['POST'])
def check_reg():
	values = request.get_json()
	required = ['client']
	if not all(k in values for k in required):
		return 'Missing values', 400
	if blockchain.check_reg(values['client'], 'client'):
		return 'Такой пользователь зарегестрирован'
	return 'Пользователь не найден'

@app.route('/authentication/key_request', methods=['GET', 'POST'])
def key_request():
	values = request.get_json()
	required = ['client']
	if not all(k in values for k in required):
		return 'Missing values', 400
	if not blockchain.check_reg(values['client'], 'client'):
		return 'Не зарегестрированный пользователь'
	pub_file = blockchain.temp_key(values['client'])
	
	return send_file(pub_file)

@app.route('/authentication/reg_user', methods=['POST'])
def reg_user():
	file = request.files['file']
	if 'file' not in request.files:
		return "Нет файла"
	if file.filename == '':
		return "Нет выбранного файла"
	filename = secure_filename(file.filename)
	file_path = os.path.join(path_user, filename)
	pubk = blockchain.get_pubkey(file_path)
	#values = request.get_json()
	values = dict(request.form)
	required = ['client']
	if not all(k in values for k in required):
		return 'Missing values', 400
	if blockchain.check_reg(values['client'], 'client'):
		return 'Такой пользователь уже зарегестрирован'
	blockchain.registration_user(values['client'], pubk)
	return 'Пользователь зарегестрирован!'

@app.route('/service/synchronization', methods=['GET'])
def synchronization():
	if (blockchain.valid_chain()) and (blockchain.check_config()):
		with open(path_config, 'r') as file:
			data = json.load(file)
		response = {'chain':blockchain.chain, 'config':data}
		#print('ok')
		return response

@app.route('/service/synchronization_all', methods=['POST'])
def synchronization_all():
	#values = dict(request.form)
	values = request.get_json()
	blockchain.update_Blockchain(values)
	return 'ok'

@app.route('/service/check_signature', methods=['POST', 'GET'])
def check_signature():
	values = request.get_json()
	required = ['id_device', 'hash_transaction', 'signature']
	if not all(k in values for k in required):
		return 'Missing values', 400
	res = blockchain.check_signature(values['id_device'], values['hash_transaction'], values['signature'])
	result = {'result_check':res}
	return result

@app.route('/chain', methods=['GET'])
def full_chain():
    response = {
		'chain': blockchain.chain,
		'length': len(blockchain.chain),
	}
    return jsonify(response), 200

@app.route('/valid', methods=['GET'])
def check_valid():
	if (blockchain.valid_chain()):
		return 'Блокчейн валидный'
	return "Блокчейн не валидный"

@app.route('/check_config', methods=['GET'])
def check_config():
	result = blockchain.check_config()
	if result:
		return "Конфиг валидный"
	return "Конфиг не валидный"

#Изменяем в 3 блоке значения пред. хэша
@app.route('/atack', methods=['POST'])
def atacked_titan():
	values = request.get_json()
	blockchain.chain[2]['previous_hash'] = 'abc'
	return "Блокчейн изменен"

if __name__ == '__main__':
    app.run(host=ip, port=port)
    #app.run(host=ip, port=port, debug=True)
