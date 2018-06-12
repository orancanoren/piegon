from cryptoran.cryptosuite.BlockCiphers import AES
import socket
import pickle

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
s.connect((TCP_IP, TCP_PORT))
sendMessage(cipher, 'hey there server!', s)
serializedData = s.recv(BUFFER_SIZE)
print('received:', decodeReceived(cipher, serializedData))
s.close()