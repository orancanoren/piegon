import pickle
from cryptoran import BlockCiphers
import socket
from abc import abstractclassmethod, ABC

class EspionageConnection(ABC):
    def __init__(self,ip, port, messageHandler):
        self.ip = ip
        self.port = port
        self.messageHandler = messageHandler
        super().__init__()

    def sendUnencrypted(self, data, sock: socket.socket):
        rawData = pickle.dumps(data)
        sock.send(rawData)

    def decodeUnencrypted(self, data: bytes):
        return pickle.loads(data)

    def sendMessage(self, msg: str, clientPair):
        if not clientPair[1]:
            self.sendUnencrypted(msg, clientPair[0])
            return

        ciphertextBlocks = clientPair[1].encrypt(msg)
        serializedBlocks = pickle.dumps(ciphertextBlocks)
        clientPair[0].send(serializedBlocks)

    def decodeReceived(self, received: bytes, cipher: BlockCiphers):
        message = pickle.loads(received)
        if cipher:
            message = cipher.decrypt(message)
        return message
    
    @abstractclassmethod
    def listen(self):
        pass

    @abstractclassmethod
    def start(self):
        pass

    @abstractclassmethod
    def stop(self):
        pass