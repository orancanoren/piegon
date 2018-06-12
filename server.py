from cryptoran.cryptosuite.BlockCiphers import AES
import pickle
import socket

TCP_IP = '127.0.0.1'
TCP_PORT = 5005
BUFFER_SIZE = 4096
AES_KEY = 0x91f646fdeed609aae15538d85bad73ac
AES_IV = 0xe28b65741a4f6d4694c42bb717fd4f80

cipher = AES('cbc', 0x91f646fdeed609aae15538d85bad73ac, 
    0xe28b65741a4f6d4694c42bb717fd4f80)

def sendMessage(cipher: AES, msg, conn):
    ciphertextBlocks = cipher.encrypt(msg)
    serializedBlocks = pickle.dumps(ciphertextBlocks)
    conn.send(serializedBlocks)

def decodeReceived(cipher: AES, received):
    ciphertextBlocks = pickle.loads(received)
    decryptedMessage = cipher.decrypt(ciphertextBlocks)
    return decryptedMessage

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((TCP_IP, TCP_PORT))
s.listen(1)
print('Listening on port', TCP_PORT)

conn, addr = s.accept()
print(addr, 'connected')

while True:
    serializedData = conn.recv(BUFFER_SIZE)
    if not serializedData:
        continue
    incomingPayload = decodeReceived(cipher, serializedData)
    print(f'from {str(addr)}:', incomingPayload)
    sendMessage(cipher, 'hey there client! thanks for connecting', conn)
conn.close()