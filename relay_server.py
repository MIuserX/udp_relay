#!/usr/bin/python
# encoding: utf-8

import select
import socket
import struct
import time
import logging
from common import *


# 1> listen a UDP port, accept data from kcptun client
# 2> listen a UDP port, receive data replied from relay_server
# 
# Session:
#   kcptun client - ip:port
#   last_data_time
#
# Tunnel:
#   UDP socket
#   expire_time
#   max_bytes
#   sent_bytes
# 
#
# Data in:
#     relay_client =>  : listen_sock
#     kcptun server => : session socks
# Data out:
#     => relay_client  : tunnel socks
#     => kcptun server : session socks

Logger = logging.getLogger('relay_server')
Logger.setLevel(logging.DEBUG)
fh = logging.FileHandler('/var/log/relay/server.log')
fh.setLevel(logging.INFO)
fmt = logging.Formatter('[%(asctime)s] %(levelname)s: %(message)s')
fh.setFormatter(fmt)
Logger.addHandler(fh)

sh = logging.StreamHandler()
sh.setLevel(logging.DEBUG)
sh.setFormatter(fmt)
# Logger.addHandler(sh)


select_timeout = 1

class RelayServer:

    send_line_max = 8

    def __init__(self, conf):
        try:
            self.session_timeout = conf['session_timeout']
            self.tunnel_timeout = conf['tunnel_lifetime']

            self.listen_addr = conf['listen_addr']
            self.listen_port = conf['listen_port']
            self.listen_sock = None

            self.remote_addr = conf["remote_addr"]
            self.remote_port = conf["remote_port"]
            self.sessions = {} # "cli_ip:cli_port": session

            self.local_addrs = conf["local_addrs"]
            self.reply_addrs = conf["reply_addrs"]
            self.tunnels = []  # tunnel
            self.tun_i = 0

            self.r_socks = []
        except Exception as e:
            raise Exception("args error ~ {0}".format(str(e)))

        try:
            self.listen_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.listen_sock.bind((self.listen_addr, self.listen_port))
            self.listen_sock.setblocking(False)
            self.r_socks.append(self.listen_sock)
        except Exception as e:
            if len(self.r_socks) > 0:
                for s in self.r_socks:
                    s.close()
            raise Exception("UDP listen error ~ {0}".format(str(e)))

        try:
            for addr in self.local_addrs:
                dst_ip = self.reply_addrs[0]['ip']
                dst_port = getAPort(self.reply_addrs[0]['port_range'])
                tunnel = ServTunnel(addr['ip'], addr['port_range'], dst_ip, dst_port, self.tunnel_timeout)
                self.tunnels.append(tunnel)
        except Exception as e:
            if len(self.r_socks) > 0:
                for s in self.r_socks:
                    s.close()
            if len(self.tunnels) > 0:
                for t in self.tunnels:
                    self.tunnels.remove(t)
            raise Exception("create tunnels error ~ {0}".format(str(e)))

    def __del__(self):
        if len(self.r_socks) > 0:
            for s in self.r_socks:
                s.close()
        if len(self.tunnels) > 0:
            for t in self.tunnels:
                self.tunnels.remove(t)

    def __getATun(self):
        if len(self.tunnels) > 0:
            self.tun_i = (self.tun_i + 1) % len(self.tunnels)
            return (self.tunnels)[self.tun_i]
        return None

    def __getSessionBySock(self, s):
        for session in self.sessions.values():
            if session.sock is s:
                return session
        return None

    def __sendToTunnel(self, pkt, t=None):
        try:
            if not t:
                t = self.__getATun()
            #Logger.debug("sentToTunnel: dst_ip=" + t.dst_ip + " dst_port=" + str(t.dst_port))
            t.sock.sendto( pkt.payload(), (t.dst_ip, t.dst_port) )
        except Exception as e:
            raise Exception("sendToTunnel failed, {0}".format(str(e)))

    def __processPayload(self, payload):
        try:
            pkt = Packet.parsePkt(payload)
            session_key = pkt.ip + ':' + str(pkt.port)
    
            if session_key not in self.sessions:
                try:
                    new_session = ServSession(
                            self.session_timeout,
                            pkt.ip, 
                            pkt.port)
                    self.sessions[session_key] = new_session
                    self.r_socks.append(new_session.sock)
                    Logger.info("new sesseion " + session_key)
                except Exception as e:
                    raise Exception("new session error ~ " + str(e))
    
            if pkt.isPSH():
                try:
                    self.sessions[session_key].update()
                    self.sessions[session_key].sock.sendto(pkt.data, (self.remote_addr, self.remote_port))
                except Exception as e:
                    raise Exception("send to target error ~ " + str(e))

            if pkt.isFIN():
                self.r_socks.remove(self.sessions[session_key].sock)
                del self.sessions[session_key]
                Logger.debug("client wants to delete session [" + session_key + "]")
        except Exception as e:
            raise Exception("processPayload failed ~ " + str(e))

    def loop(self):
        outputs = []

        while True:
            readable , writable , exceptional = select.select(
                    self.r_socks, 
                    outputs, 
                    self.r_socks, 
                    select_timeout)

            #### process read events
            for sock in readable:
                if sock is self.listen_sock:
                    # 1> receive packet
                    # 2> new session and add it to r_socks 
                    #    or update session time
                    # 3> send data across the session

                    payload = None
                    remote_tun_addr = None
                    try:
                        payload, remote_tun_addr = sock.recvfrom(2048)
                        # Logger.debug("UDP Packet, len={0} addr={1}".format(str(len(payload)), str(remote_tun_addr)))
                        if payload:
                            self.__processPayload(payload)
                        else:
                            Logger.error("payload is None")
                    except Exception as e:
                        raise Exception("recv request error ~ {}".format(str(e)))
                else:
                    # 1> receive UDP data
                    # 2> search session by sock
                    # 3> send packet with session's ip:port as target across tunnels

                    data = None
                    _addr = None
                    try:
                        data, _addr = sock.recvfrom(2048)
                        if data:
                            session = self.__getSessionBySock(sock)
                            if session:
                                pkt = Packet((session.ip, session.port), data)
                                pkt.setPSH()
                                self.__sendToTunnel(pkt)
                            else:
                                Logger.error("session " + session.ip + ':' + str(session.port) + " not found")
                        else:
                            Logger.error('data is None')
                    except Exception as e:
                        raise Exception("recv reply error ~ " + str(e))

            #### process expired tunnels
            # 1> give a dst_ip:dst_port
            # 2> new tunnel
            for t in self.tunnels:
                if t.isExpired():
                    tun_key = t.local_ip + ':' + str(t.local_port) +\
                        '<=>' + t.dst_ip + ':' + str(t.dst_port)
                    Logger.debug("expired tunnel [" + tun_key + "]")

                    dst_ip = self.reply_addrs[0]['ip']
                    dst_port = getAPort(self.reply_addrs[0]['port_range'])

                    t.refresh(dst_ip, dst_port)

            #### process expired sessions
            for session_key, session in self.sessions.items():
                if session.isExpired():
                    Logger.info('expired session['+session_key+']')
                    self.r_socks.remove(session.sock)
                    del self.sessions[session_key]


if __name__ == '__main__':
    # listen_addr, listen_port : relay_server UDP listen
    # remote_dddr, remote_port :
    # reply_addr, reply_port_range : 
    # 
    conf = {
        "listen_addr": "0.0.0.0",
        "listen_port": 30002,
        "remote_addr": "127.0.0.1",
        "remote_port": 30001,

        "reply_addrs": [
            {
                "ip": "172.16.100.13",
                "port_range": (20001, 30000)
            }
        ],
        "local_addrs": [
            {
                "ip": "172.16.100.3",
                "port_range": (20001, 30000)
            },
            {
                "ip": "172.16.100.17",
                "port_range": (20001, 30000)
            }
        ],

        "session_timeout": 60,
        "tunnel_lifetime": 30
    }

    try:
        server = RelayServer(conf)
        server.loop()
    except Exception as e:
        print("Error: {}".format(str(e)))