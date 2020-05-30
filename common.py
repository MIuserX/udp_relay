# encoding: utf-8


import socket
import struct
import time
import random


class Packet:
    head_len = 10

    CMD_FIN = 1     # 
    CMD_FINACK = 2  # 
    CMD_PUSH = 3    #

    FLAG_SYN = 0x01  # create a session
    FLAG_PSH = 0x02  # send data
    FLAG_FIN = 0x04  # close a session

    def __init__(self, addr, data):
        self.ip = addr[0]
        self.port = addr[1]
        self.flags = 0x00
        self.cmd = 0
        self.data = data
        self.pkt_len = len(self.data) + Packet.head_len

    def isSYN(self):
        if self.flags & Packet.FLAG_SYN > 0:
            return True
        return False
    
    def isPSH(self):
        if self.flags & Packet.FLAG_PSH > 0:
            return True
        return False

    def isFIN(self):
        if self.flags & Packet.FLAG_FIN > 0:
            return True
        return False

    def setSYN(self):
        self.flags |= Packet.FLAG_SYN

    def setPSH(self):
        self.flags |= Packet.FLAG_PSH

    def setFIN(self):
        self.flags |= Packet.FLAG_FIN

    def payload(self):
        return socket.inet_aton(self.ip) + \
                struct.pack('!HHBB', self.port, self.pkt_len, self.flags, self.cmd) + \
                self.data

    @staticmethod
    def parseHead(pkt):
        obj = Packet(('', 0), '')
        try:
            obj.ip = socket.inet_ntoa(pkt[0:4])
            obj.port = int( (struct.unpack('!H', pkt[4:6]))[0] )
            obj.pkt_len = int( (struct.unpack('!H', pkt[6:8]))[0] )
            obj.flags = int( (struct.unpack('!B', pkt[8:9]))[0] )
            obj.cmd = int( (struct.unpack('!B', pkt[9:10]))[0] )
        except Exception as e:
            raise Exception("Parsing packet head failed, " + str(e))
        return obj
    
    @staticmethod
    def parsePkt(pkt):
        obj = Packet(('', 0), '')
        try:
            obj.ip = socket.inet_ntoa(pkt[0:4])
            obj.port = int( (struct.unpack('!H', pkt[4:6]))[0] )
            obj.head_len = int( (struct.unpack('!H', pkt[6:8]))[0] )
            obj.flags = int( (struct.unpack('!B', pkt[8:9]))[0] )
            obj.cmd = int( (struct.unpack('!B', pkt[9:10]))[0] )
            obj.data = pkt[10:]
        except Exception as e:
            raise Exception("Parsing packet failed, " + str(e))
        return obj


class CliTunnel:

    def __init__(self, dst_ip, dst_port_range, timeout):
        self.dst_ip = dst_ip
        self.dst_port = 0
        self.dst_port_range = dst_port_range
        self.birth_time = None
        self.timeout = timeout
        self.sock = None

        try:
            self.__newSock()
        except Exception as e:
            raise Exception("new tunnel error ~ " + str(e))

    def __newSock(self):
        self.dst_port = getAPort(self.dst_port_range)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setblocking(False)
        self.birth_time = time.time()

    def refresh(self):
        if self.sock:
            self.sock.close()
            self.sock = None
        self.__newSock()

    def isExpired(self):
        if time.time() > self.birth_time + self.timeout:
            return True
        return False


class ServTunnel:

    retry_max = 3

    def __init__(self, local_ip, local_port_range, dst_ip, dst_port, timeout):
        self.local_ip = local_ip
        self.local_port = local_port_range[0]

        self.local_port_range = local_port_range
        self.port_offset = 0

        self.dst_ip = dst_ip
        self.dst_port = dst_port

        self.timeout = timeout

        self.__newSock()

    def __newSock(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        retry = 0
        while True:
            try:
                self.local_port = getAPort(self.local_port_range)
                # print("Debug: will bind " + self.local_ip + ':' + str(self.local_port))
                self.sock.bind((self.local_ip, self.local_port))
                break
            except Exception as e:
                if retry <= ServTunnel.retry_max:
                    print("Warning: bind port error - " + str(e))
                else:
                    raise Exception("bind port error ~ " + str(e))
                retry += 1

        self.sock.setblocking(False)

        self.birth_time = time.time()

    def refresh(self, dst_ip, dst_port):
        self.dst_ip = dst_ip
        self.dst_port = dst_port

        if self.sock:
            self.sock.close()
        self.__newSock()

    def isExpired(self):
        if time.time() > self.birth_time + self.timeout:
            return True
        return False


class Session:

    def __init__(self, timeout, _ip='0.0.0.0', _port=0):
        self.ip = _ip
        self.port = _port
        self.timeout = timeout
        self.last_data_time = time.time()

    def isExpired(self):
        if time.time() > self.last_data_time + self.timeout:
            return True
        return False

    def update(self):
        self.last_data_time = time.time()


class ServSession:
    def __init__(self, timeout, _ip, _port):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setblocking(False)

        self.ip = _ip
        self.port = _port

        self.timeout = timeout
        self.last_data_time = time.time()

    def __del__(self):
        if self.sock:
            self.sock.close()

    def update(self):
        self.last_data_time = time.time()

    def isExpired(self):
        if time.time() > self.last_data_time + self.timeout:
            return True
        return False


def getIpAndPort(addr):
    columns = addr.split(":")
    return columns[0], int(columns[1])


def getAPort(port_range):
    cnt = port_range[1] - port_range[0] + 1
    x = random.randint(0, cnt-1)
    return port_range[0] + x


if __name__ == '__main__':
    print("hello")