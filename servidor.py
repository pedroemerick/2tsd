import socket 
import base64
from Crypto.Cipher import AES
import secrets
import hashlib
import json

#Definindo variáveis e dados de conexão
host = ''
port = 3000
addr = (host, port)
Dados_Clientes = {"id": []}
unidades_aut = {}

#Inicializando o socket para receber conexões
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind(addr)
sock.listen(3)

while True:
	
	print("\nAguardando Conexão...\n")
	
	c, cliente = sock.accept()
	
	print ("Unidade Autenticadora Conectada - ", cliente[0], ":", cliente[1])
	
	mensagem = c.recv(2048)
	mensagem = json.loads(mensagem.decode())
	
	op = mensagem.get("op")

	if op == 0:
		
		print("Registrando Unidade Autenticadora...")
		
		va = mensagem.get("va")
		vb = mensagem.get("vb")
		hash = mensagem.get("hash")
		
		va_xor_vb = int(va, 16) ^ int(vb, 16)
		va_xor_vb = format(va_xor_vb, 'x')
		
		hash_va_vb = hashlib.sha1(str(va_xor_vb).encode("utf-8")).hexdigest()
		
		if (hash_va_vb == hash):
			
			random_vc = secrets.token_hex(8)
			
			va_vb_xor_vc = int(va_xor_vb, 16) ^ int(random_vc, 16)
			va_vb_xor_vc = format(va_vb_xor_vc, 'x')
			
			hash_va_vb_vc = hashlib.sha1(str(va_vb_xor_vc).encode("utf-8")).hexdigest()
			
			send = json.dumps({"vc": random_vc, "hash": hash_va_vb_vc})
			
			c.send(send.encode())
			
			key = (int(va, 16) ^ int(random_vc, 16)) ^ int(vb, 16)
			key = format(key, 'x')
			
			iv = (int(va, 16) ^ int(vb, 16)) ^ int(random_vc, 16)
			iv = format(iv, 'x')
			
			hash_key = hashlib.sha1(str(key).encode("utf-8")).hexdigest()
			
			message = c.recv(2048)
			message = json.loads(message.decode())
			
			hash_key_aut = message.get("hash")
			
			if (hash_key == hash_key_aut):
				
				random_vd = secrets.token_hex(8)
				
				id = int(random_vd, 16) ^ (int(vb, 16) ^ int(random_vc, 16))
				id = format(id, 'x')
				
				hash_id = hashlib.sha1(str(id).encode("utf-8")).hexdigest()
				
				send = json.dumps({"vd": random_vd, "id": id, "hash": hash_id})
				send = send.ljust((16 - (len(send) % 16)) + len(send))
				send = send.encode()
				
				aes = AES.new(key, AES.MODE_CBC, iv)
				data_enc = aes.encrypt(send)
				
				c.send(base64.b64encode(data_enc))
				
				unidades_aut[id] = {"key": key, "iv": iv}
				
				print("Unidade Autenticadora Registrada!\nID enviado!")
				
			else:
				print("[ERRO] Chave de Criptografia Inválida!")
				
		else:
			print("[ERRO] Dados Inválidos!")

	if op == 1:
		
		print("Registrando um novo cliente...")
		
		ID = mensagem.get("id")
		Dados_Clientes["id"].append(ID)
		
		print("Cliente Registrado: ", ID)
	
	if op == 2:
		
		print("Recebendo dados...")
		
		ID_auth = mensagem.get("id_auth")
		
		if ID_auth in unidades_aut:
		
			ID_cliente = mensagem.get("id_cliente")
			dados = mensagem.get("dados")
			
			aes_dec = AES.new(unidades_aut[ID_auth].get("key"), AES.MODE_CFB, unidades_aut[ID_auth].get("iv"))

			ID_cliente = base64.b64decode(ID_cliente)
			ID_cliente = aes_dec.decrypt(ID_cliente)
			ID_cliente = ID_cliente.decode("utf-8")

			dados = base64.b64decode(dados)
			dados = aes_dec.decrypt(dados)
			dados = dados.decode("utf-8")
			
			print(ID_cliente, " - Dados Recebidos: ", dados)
	
sock.close()

