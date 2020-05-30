# encoding: utf-8


import socket
import struct
import time
import random
import os
import sys
import atexit


def daemonize(pid_file=None):
    """
    创建守护进程
    :param pid_file: 保存进程id的文件
    :return:
    """
    # 从父进程fork一个子进程出来
    pid = os.fork()
    # 子进程的pid一定为0，父进程大于0
    if pid:
        # 退出父进程
        sys.exit(0)
 
    # 子进程默认继承父进程的工作目录，最好是变更到根目录，否则回影响文件系统的卸载
    os.chdir('/')
    # 子进程默认继承父进程的umask（文件权限掩码），重设为0（完全控制），以免影响程序读写文件
    os.umask(0)
    # 让子进程成为新的会话组长和进程组长
    os.setsid()
 
    # 注意了，这里是第2次fork，也就是子进程的子进程，我们把它叫为孙子进程
    _pid = os.fork()
    if _pid:
        # 退出子进程
        sys.exit(0)
 
    # 此时，孙子进程已经是守护进程了，接下来重定向标准输入、输出、错误的描述符(是重定向而不是关闭, 这样可以避免程序在 print 的时候出错)
 
    # 刷新缓冲区先，小心使得万年船
    sys.stdout.flush()
    sys.stderr.flush()
 
    # dup2函数原子化地关闭和复制文件描述符，重定向到/dev/nul，即丢弃所有输入输出
    with open('/dev/null') as read_null, open('/dev/null', 'w') as write_null:
        os.dup2(read_null.fileno(), sys.stdin.fileno())
        os.dup2(write_null.fileno(), sys.stdout.fileno())
        os.dup2(write_null.fileno(), sys.stderr.fileno())
 
    # 写入pid文件
    if pid_file:
        with open(pid_file, 'w+') as f:
            f.write(str(os.getpid()))
        # 注册退出函数，进程异常退出时移除pid文件
        atexit.register(os.remove, pid_file)


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
        self.local_port = 0
        self.local_port_range = local_port_range

        self.dst_ip = dst_ip
        self.dst_port = dst_port

        self.timeout = timeout

        self.sent_bytes = 0

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
                if retry > ServTunnel.retry_max:
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