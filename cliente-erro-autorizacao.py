import socket
import hashlib
import base64
from Crypto.Cipher import AES
import json

#Definindo variáveis e dados de conexão
host = ''
port = 4000
addr = ((host,port))

ID = "123123123"

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
