import socket
import hashlib
import base64
from Crypto.Cipher import AES
import json
import secrets

# Definindo variáveis
ids_Clientes = []
ivs_Clientes = []
chaves_Clientes = []
cont_registros = -1

# Dados para conexão ao servidor
host_servidor = '127.0.0.1'
port_servidor = 3000
addr_servidor = ((host_servidor,port_servidor))

# Primeiro a o autenticador precisará se autenticar no servidor
sock_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock_server.connect(addr_servidor)

print("Conectado ao Servidor...")
print("Solicitando Registro...")

# Iniciando processo de registro no servidor
random_va = secrets.token_hex(8)
random_vb = secrets.token_hex(8)

result_xor = int(random_va, 16) ^ int(random_vb, 16)
result_xor = format(result_xor, 'x')

hash = hashlib.sha1(str(result_xor).encode("utf-8")).hexdigest()

send = json.dumps({"op": 0, "va": random_va, "vb": random_vb, "hash": hash})
sock_server.send(send.encode())

message = sock_server.recv(2048)
message = json.loads(message.decode())

vc = message.get("vc")

key = (int(random_va, 16) ^ int(vc, 16)) ^ int(random_vb, 16)
key = format(key, 'x')

iv_aut = (int(random_va, 16) ^ int(random_vb, 16)) ^ int(vc, 16)
iv_aut = format(iv_aut, 'x')

hash_key = hashlib.sha1(str(key).encode("utf-8")).hexdigest()

send = json.dumps({"hash": hash_key})
sock_server.send(send.encode())

message = sock_server.recv(2048)
message = base64.b64decode(message)

aes = AES.new(key, AES.MODE_CBC, iv_aut)
data_dec = aes.decrypt(message)

message = json.loads(data_dec)

vd = message.get("vd")
hash_id_server = message.get("hash")

id = int(vd, 16) ^ (int(random_vb, 16) ^ int(vc, 16))
id = format(id, 'x')

hash_id = hashlib.sha1(str(id).encode("utf-8")).hexdigest()

if (hash_id == hash_id_server):
    print("Registrado com Sucesso!")
    print("ID Recebido: " + str(id))
else:
    print("[ERRO] Criação do ID Inválida!")
	
sock_server.close()

#Inicializando o socket para receber conexões
host = ''
port = 4000
addr = (host, port)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind(addr)
sock.listen(3)

# Loop para aguardar o recebimento de requisições
while True:

	print("\nAguardando Conexão...\n")
	
	# Aceitando conexões
	c, cliente = sock.accept()
	
	print ("Cliente Conectado - ", cliente[0], ":", cliente[1])
	
	# Recebe os dados do cliente
	mensagem = c.recv(2048)
	
	#Decodificando a mensagem recebida
	mensagem = json.loads(mensagem.decode())
	
	op = mensagem.get("op")
	
	# Caso a mensagem foi uma requisição para um cliente se registrar
	if op == 1:
		print("Registrando um novo cliente...")
		
		# Armazena o valor randômico gerado pelo cliente
		rand_1 = mensagem.get("randomico")
		
		# Gera o segundo valor randômico
		rand_2 = secrets.token_hex(8)
		
		# Operação XOR
		xor_rand1_rand2 = int(rand_1, 16) ^ int(rand_2, 16)
		
		# Processo de codificação antes de tirar o hash
		xor_rand1_rand2 = format(xor_rand1_rand2, 'x')
		xor_rand1_rand2 = xor_rand1_rand2.encode()
		
		# Hash do resultado da operação XOR
		hash_rand1_rand2 = hashlib.sha1(xor_rand1_rand2).hexdigest()
		
		mensagem = json.dumps({"randomico": rand_2, "hash": hash_rand1_rand2})
		mensagem = mensagem.encode()
		
		# Envia o pacote com o valor randômico e o hash
		c.send(mensagem)
		
		# Recebe a resposta contendo o hash
		hash_chave_recebido = c.recv(2048)
		hash_chave_recebido = hash_chave_recebido.decode()
		
		#Hash do valor randômico 1
		rand_1 = rand_1.encode()
		hash_rand1 = hashlib.sha1(rand_1).hexdigest()
		
		#Hash do valor randômico 2
		rand_2 = rand_2.encode()
		hash_rand2 = hashlib.sha1(rand_2).hexdigest()
		
		#Gera a chave de criptografia
		xor_hash = int(hash_rand1, 16) ^ int(hash_rand2, 16)
		xor_hash = format(xor_hash, 'x')
		xor_hash = xor_hash.encode()
		
		#Hash do resultado da chave de criptografia
		hash_chave = hashlib.sha1(xor_hash).hexdigest()
		
		if hash_chave_recebido == hash_chave:
			
			rand_3 = secrets.token_hex(8)
			
			iv = (int(rand_3, 16) ^ int(rand_1, 16)) ^ int(rand_2, 16)
			iv = format(iv, 'x')

			chave = (int(rand_1, 16) ^ int(rand_2, 16)) ^ int(rand_3, 16)
			
			ID = secrets.token_hex(8)
			
			xor_iv_ID = int(iv, 16) ^ int(ID, 16)
			xor_iv_ID = format(xor_iv_ID, 'x')
			xor_iv_ID = xor_iv_ID.encode()
			
			hash_xor_iv_ID = hashlib.sha1(xor_iv_ID).hexdigest()
			
			mensagem = json.dumps({"randomico": rand_3, "id": ID, "hash": hash_xor_iv_ID})
			mensagem = mensagem.encode()
			
			ids_Clientes.append(ID)
			ivs_Clientes.append(iv)
			chaves_Clientes.append(chave)
			
			print("Cliente registrado com sucesso!")
			print("ID Enviado!")
			
			#Envia o pacotes com os dados de registro do cliente
			c.send(mensagem)
		else:
			print("[ERRO] Chave de Criptografia Inválida!")
		
		
		#Criando o socket para se comunicar com o servidor
		sock_serv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock_serv.connect(addr_servidor)
		
		print("Enviando ID do cliente registrado ao servidor...")
		
		mensagem = json.dumps({"op": 1, "id": ID})
		mensagem = mensagem.encode()
		
		sock_serv.send(mensagem)
		
		#Fechando conexão com o servidor
		sock_serv.close()
		
	#Caso a mensagem for uma solicitação de autorização para um cliente se comunicar
	if op == 2:
		
		print("Solicitação de Comunicação...")
	
		ID = mensagem.get("id")
		
		rand_5 = secrets.token_hex(8)
		
		#Procura pelo ID do cliente que está fazendo a solicitação
		cont_registros = -1
		for i in range(len(ids_Clientes)):	
			if ids_Clientes[i] == ID:
				cont_registros = i
		
		if cont_registros == -1:
			mensagem = json.dumps({"erro": "Não autorizado!"})
			
			print ("Cliente não autorizado!")
			
			c.send(mensagem.encode("utf-8"))
		else:
			xor_chave_id = int(chaves_Clientes[cont_registros]) ^ int(ids_Clientes[cont_registros], 16)
			xor_chave_id = format(xor_chave_id, 'x')
			xor_chave_id = xor_chave_id.encode()
			
			hash_xor_chave_id = hashlib.sha1(xor_chave_id).hexdigest()
			
			mensagem = json.dumps({"randomico": rand_5, "hash": hash_xor_chave_id})
			mensagem = mensagem.encode('utf-8')
			
			c.send(mensagem)
			
			mensagem = c.recv(2048)
			
			chaves_Clientes[cont_registros] = format(chaves_Clientes[cont_registros], 'x')

			#Descriptografia
			aes_dec = AES.new(chaves_Clientes[cont_registros], AES.MODE_CFB, ivs_Clientes[cont_registros])
			mensagem_dec = aes_dec.decrypt(base64.b64decode(mensagem))
			
			mensagem_dec = json.loads(mensagem_dec.decode())
			
			dados_recebidos = mensagem_dec.get("dados")
			hash_recebido = mensagem_dec.get("hash")
			
			xor_rand5_chave_id = (int(rand_5, 16) ^ int(chaves_Clientes[cont_registros], 16)) ^ int(ids_Clientes[cont_registros], 16)
			xor_rand5_chave_id = format(xor_rand5_chave_id, 'x')
			xor_rand5_chave_id = xor_rand5_chave_id.encode()

			hash_xor_rand5_chave_id = hashlib.sha1(xor_rand5_chave_id).hexdigest()

			if hash_recebido == hash_xor_rand5_chave_id:
			
				print("Cliente Autorizado e Dados Recebidos!")
				
				#Criando o socket para se comunicar com o servidor
				sock_serv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				sock_serv.connect(addr_servidor)
				
				print ("Enviando dados ao servidor...")
				
				aes_enc = AES.new(key, AES.MODE_CFB, iv_aut)

				ID_cliente = aes_enc.encrypt(ids_Clientes[cont_registros])
				ID_cliente = base64.b64encode(ID_cliente)
				ID_cliente = ID_cliente.decode("utf-8")

				dados = aes_enc.encrypt(dados_recebidos)
				dados = base64.b64encode(dados)
				dados = dados.decode("utf-8")
				
				mensagem = json.dumps({"op": 2, "id_auth": id, "id_cliente": ID_cliente, "dados": dados})
				mensagem = mensagem.encode("utf-8")
				
				sock_serv.send(mensagem)
				
				print ("Dados enviados!")
				
				#Fechando conexão com o servidor
				sock_serv.close()
		
#Fecha a conexão TCP
sock.close()
