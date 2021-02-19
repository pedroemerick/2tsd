import socket
import hashlib
import random, string, base64
from Crypto.Cipher import AES
import json
import secrets


#Definindo variáveis e dados de conexão
host = '192.168.20.3'
port = 3000
addr = ((host,port))


#Inicializando o socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

#Conectando-se com o autenticador
sock.connect(addr)

print ("Conectado à Unidade Autenticadora...")

print ("Solicitando registro...")

#Gera o primeiro valor randômico
rand_1 = secrets.token_hex(8)

#Cria o json para formar o pacote de requisição para fazer o registro do cliente
mensagem_requisicao = json.dumps({"op": 1, "randomico": rand_1})

mensagem_requisicao = mensagem_requisicao.encode()

#Enviando a mensagem codificada para o autenticador
sock.send(mensagem_requisicao)

#Recebe a resposta do Autenticador
mensagem_resposta = sock.recv(2048)

mensagem_resposta = json.loads(mensagem_resposta.decode())

rand_2 = mensagem_resposta.get("randomico")

hash_rand1_rand2_recebido = mensagem_resposta.get("hash")

#Operação XOR
xor_rand1_rand2 = int(rand_1, 16) ^ int(rand_2, 16)

#Processo de codificação antes de tirar o hash
xor_rand1_rand2 = format(xor_rand1_rand2, 'x')

xor_rand1_rand2 = xor_rand1_rand2.encode()

#Hash do resultado da operação XOR
hash_rand1_rand2 = hashlib.sha1(xor_rand1_rand2).hexdigest()

if hash_rand1_rand2_recebido == hash_rand1_rand2:
	
	#Hash do valor randômico 1
	rand_1 = rand_1.encode()
	
	hash_rand1 = hashlib.sha1(rand_1).hexdigest()
	
	#Hash do valor randômico 2
	rand_2 = rand_2.encode()
	
	hash_rand2 = hashlib.sha1(rand_2).hexdigest()
	
	xor_hash = int(hash_rand1, 16) ^ int(hash_rand2, 16)
	
	#Hash do resultado da chave de criptografia
	xor_hash = format(xor_hash, 'x')
	
	xor_hash = xor_hash.encode()
	
	hash_chave = hashlib.sha1(xor_hash).hexdigest()
	
	#Envia o hash para o Autenticador
	sock.send(hash_chave.encode())
	
	#Recebe os dados de registro gerados pelo autenticador
	mensagem_resposta = sock.recv(2048)
	
	mensagem_resposta = json.loads(mensagem_resposta.decode())
	
	rand_3 = mensagem_resposta.get("randomico")
	
	ID = mensagem_resposta.get("id")
	
	hash_recebido = mensagem_resposta.get("hash")
	
	#Realiza as mesmas operações feitas pelo autenticador para validar os dados de registro
	iv = (int(rand_3, 16) ^ int(rand_1, 16)) ^ int(rand_2, 16)
	
	chave = (int(rand_1, 16) ^ int(rand_2, 16)) ^ int(rand_3, 16)
	
	iv = format(iv, 'x')
	
	xor_iv_ID = int(iv, 16) ^ int(ID, 16)
	
	xor_iv_ID = format(xor_iv_ID, 'x')
	
	xor_iv_ID = xor_iv_ID.encode()
	
	hash_xor_iv_ID = hashlib.sha1(xor_iv_ID).hexdigest()
	
	if hash_xor_iv_ID == hash_recebido:
		print("Registrado com sucesso!")
		print("ID Recebido: ", ID)
		
		sock.close()
	
	else:
		print ("[ERRO] Chave de Criptografia Inválida!")
		sock.close()
	
	
else:
	print ("[ERRO] Dados gerados incorretamente!")
	sock.close()


#Conectando-se com o autenticador
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

sock.connect(addr)

print ("\nConectado à Unidade Autenticadora...")

print ("Solicitando autorização para envio de dados...")

#Cria o json para formatar o pacote de solicitação de autorização para se comunicar
mensagem_solicitacao = json.dumps({"op": 2, "id": ID})

mensagem_solicitacao = mensagem_solicitacao.encode()

sock.send(mensagem_solicitacao)

mensagem_resposta = sock.recv(2048)

mensagem_resposta = json.loads(mensagem_resposta.decode())

if "erro" in mensagem_resposta:
	
	print (mensagem_resposta.get("erro"))

else:

	rand_5 = mensagem_resposta.get("randomico")

	hash_recebido = mensagem_resposta.get("hash")

	xor_chave_id = int(chave) ^ int(ID, 16)

	xor_chave_id = format(xor_chave_id, 'x')

	xor_chave_id = xor_chave_id.encode()

	hash_xor_chave_id = hashlib.sha1(xor_chave_id).hexdigest()

	#Verifica se o hash recebido é igual ao que foi gerado agora
	if hash_recebido == hash_xor_chave_id:

		print ("Autorizado com sucesso!")
		
		dados_enviar = "Paciente 105 com febre"
		
		xor_rand5_chave_id = (int(rand_5, 16) ^ int(chave)) ^ int(ID, 16)
		
		xor_rand5_chave_id = format(xor_rand5_chave_id, 'x')

		xor_rand5_chave_id = xor_rand5_chave_id.encode()
		
		hash_xor_rand5_chave_id = hashlib.sha1(xor_rand5_chave_id).hexdigest()
		
		mensagem = json.dumps({"dados": dados_enviar, "hash": hash_xor_rand5_chave_id})
		
		mensagem = mensagem.encode()
		
		chave = format(chave, 'x')
		
		aes_enc = AES.new(chave, AES.MODE_CFB, iv)
		dados_enc = aes_enc.encrypt(mensagem)
		
		dados_enc = base64.b64encode(dados_enc)
		
		dados_enc = dados_enc.decode("utf-8")
		
		sock.send(dados_enc.encode())
		
		print ("Dados enviados!")



#Fechando conexão com o autenticador
sock.close()
