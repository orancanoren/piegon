import pickle
from cryptoran import BlockCiphers
import socket
from abc import abstractclassmethod, ABC

class EspionageConnection(ABC):
    def __init__(self, cipher: BlockCiphers.BlockCipher,
            ip, port, messageHandler):
        self.ip = ip
        self.port = port
        self.messageHandler = messageHandler
        self.cipher = cipher
        super().__init__()

    def sendMessage(self, msg: str, client: socket.socket):
        ciphertextBlocks = self.cipher.encrypt(msg)
        serializedBlocks = pickle.dumps(ciphertextBlocks)
        client.send(serializedBlocks)

    def decodeReceived(self, received):
        ciphertextBlocks = pickle.loads(received)
        decryptedMessage = self.cipher.decrypt(ciphertextBlocks)
        return decryptedMessage
    
    @abstractclassmethod
    def listen(self):
        pass

    @abstractclassmethod
    def start(self):
        pass

    @abstractclassmethod
    def stop(self):
        pass