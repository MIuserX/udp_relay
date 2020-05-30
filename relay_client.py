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
# Data in:
#     clients =>   : listen_sock
#     server  =>   : reply_sock
# Data out:
#     => server    : tunnel socks 
#     => clients   : listen_sock

Logger = logging.getLogger('relay_client')
Logger.setLevel(logging.DEBUG)
fh = logging.FileHandler('/var/log/relay/client.log')
fh.setLevel(logging.INFO)
fmt = logging.Formatter('[%(asctime)s] %(levelname)s: %(message)s')
fh.setFormatter(fmt)
Logger.addHandler(fh)



select_timeout = 1

class RelayClient:

    send_line_max = 8

    def __init__(self, conf):
        try:
            self.session_timeout = conf['session_timeout']
            self.tunnel_timeout = conf['tunnel_timeout']
            
            ## receive data from clients
            self.listen_addr = conf['listen_addr']
            self.listen_port = conf['listen_port']
            self.listen_sock = None
            self.sessions = {}  # "cli_ip:cli_port" : session 

            ## receive data from 
            self.reply_addr = conf['reply_addr']
            self.reply_port = conf['reply_port']
            self.reply_sock = None

            self.remote_addrs = conf["remote_addrs"]
            self.tunnels = []
            self.tun_i = 0

            self.r_socks = []

        except Exception as e:
            raise Exception("args error ~ {0}".format(str(e)))

        try:
            self.listen_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.listen_sock.bind((self.listen_addr, self.listen_port))
            self.listen_sock.setblocking(False)
            self.r_socks.append(self.listen_sock)
            # print("listen_sock=" + str(self.listen_sock))
        except Exception as e:
            if len(self.r_socks) > 0:
                for s in self.r_socks:
                    s.close()
            raise Exception("UDP listen clients error ~ {0}".format(str(e)))

        try:
            self.reply_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.reply_sock.bind((self.reply_addr, self.reply_port))
            self.reply_sock.setblocking(False)
            self.r_socks.append(self.reply_sock)
            # print("listen_sock=" + str(self.listen_sock))
        except Exception as e:
            if len(self.r_socks) > 0:
                for s in self.r_socks:
                    s.close()
            raise Exception("UDP listen servers error ~ {0}".format(str(e)))

        try:
            for addr in self.remote_addrs:
                self.__addATunnel(addr["ip"], addr["portRange"], self.tunnel_timeout)
                # print("sock=" + str(tunnel.sock))
        except Exception as e:
            if len(self.r_socks) > 0:
                for s in self.r_socks:
                    s.close()
            raise Exception("create tunnels failed ~ {0}".format(str(e)))

    def __del__(self):
        if len(self.r_socks) > 0:
            for s in self.r_socks:
                s.close()
    
    def __addATunnel(self, dst_ip, portRange, timeout):
        tunnel = CliTunnel(dst_ip, portRange, timeout)
        self.tunnels.append(tunnel)

    def __getATun(self):
        self.tun_i = (self.tun_i + 1) % len(self.remote_addrs)
        return self.tunnels[self.tun_i]

    def __sendToTunnel(self, pkt, t=None):
        try:
            if not t:
                t = self.__getATun()
            t.sock.sendto( pkt.payload(), (t.dst_ip, t.dst_port) )
            #from_addr = src_addr[0] + ':' + str(src_addr[1])
            #to_addr = self.remote_addr + ':' + str(self.remote_ports[self.idx])
            #print("[%s]Debug: c=>s [%20s] => [%20s] %d bytes" % (str(time.time()), from_addr, to_addr, len(pkt.data)))
        except Exception as e:
            raise Exception("sendToTunnel failed ~ " + str(e))

    def __processPayload(self, payload):
        try:
            pkt = Packet.parsePkt(payload)
            session_key = pkt.ip + ':' + str(pkt.port)
            if pkt.isPSH():
                if session_key in self.sessions:
                    self.listen_sock.sendto(pkt.data, (pkt.ip, pkt.port))
                    self.sessions[session_key].update()
                else:
                    Logger.error("bad session " + session_key)
        except Exception as e:
            raise Exception("processPayload failed ~ {0}".format(str(e)))

    def loop(self):
        outputs = []

        while True:
            #### wait events
            # print("Debug: select waiting...")
            readable , writable , exceptional = select.select(self.r_socks, outputs, self.r_socks, select_timeout)

            #### process read events
            # print("Debug: do read events")
            for sock in readable:
                if sock is self.listen_sock:
                    try:
                        data = None
                        cli_addr = None
                        data, cli_addr = sock.recvfrom(2048)
                        #print("type(data)={0}".format(str(type(data))))
                        #print("type(addr)={0}".format(str(type(src_addr))))
                        #print("Debug: UDP Packet, len={0} addr={1}".format(str(len(data)), str(src_addr)))
                        #return
                        if data:
                            pkt = Packet(cli_addr, data)
                            pkt.setPSH()

                            # 更新session时间
                            session_key = cli_addr[0] + ':' + str(cli_addr[1])
                            if session_key not in self.sessions:
                                self.sessions[session_key] = Session(
                                        self.session_timeout,
                                        cli_addr[0], 
                                        cli_addr[1]
                                    )
                                Logger.info("new sesseion " + session_key)
                                pkt.setSYN()
                            else:
                                self.sessions[session_key].update()
                            
                            # kcptun client来的数据，转发到TCP tunnels
                            self.__sendToTunnel(pkt)
                        else:
                            Logger.error("data is None")
                    except Exception as e:
                        raise Exception("recv client error! {}".format(str(e)))
                elif sock is self.reply_sock:
                    payload = None
                    _addr = None
                    try:
                        # receive packet from relay_server
                        payload, _addr = sock.recvfrom(2048)

                        # process payload
                        if payload:
                            self.__processPayload(payload)
                        else:
                            Logger.error('payload is None')
                    except Exception as e:
                        raise Exception("recv reply error! {}".format(str(e)))

            # process expired tunnels
            for t in self.tunnels:
                if t.isExpired():
                    old_tun = t.dst_ip + ':' + str(t.dst_port)
                    try:
                        t.refresh()
                    except Exception as e:
                        raise Exception("refresh tunnel error > " + str(e))
                    new_tun = t.dst_ip + ':' + str(t.dst_port)
                    Logger.debug("refresh tunnel [" + old_tun + "] => [" + new_tun + "]")

            # process expired sessions
            for session_key, session in self.sessions.items():
                if session.isExpired():
                    pkt = Packet((session.ip, session.port), 'FIN')
                    pkt.setFIN()
                    try:
                        self.__sendToTunnel(pkt)
                    except Exception as e:
                        raise Exception("send FIN error > " + str(e))
                    del self.sessions[session_key]
                    Logger.info('session['+session_key+'] expired')


def main():
    daemonize()

    Logger.info("relay_client daemon started")

    conf = {
        "listen_addr": "0.0.0.0",
        "listen_port": 30001,

        "reply_addr": "0.0.0.0",
        "reply_port": 30002,

        "remote_addrs": [
            {
                "ip": "172.16.100.3",
                "portRange": (20001, 30000)
            },
            {
                "ip": "172.16.100.17",
                "portRange": (20001, 30000)
            }
        ],
        "session_timeout": 60,
        "tunnel_timeout": 30
    }

    try:
        cli = RelayClient(conf)
        cli.loop()
    except Exception as e:
        Logger.error(str(e))


if __name__ == '__main__':
    main()