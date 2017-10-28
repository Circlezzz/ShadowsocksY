#!/usr/bin/env python3
#-*- coding:utf-8 -*-

import getopt
import hashlib
import json
import logging
import os
import select
import socket
import socketserver
import struct
import sys
import time

import cryptography


def getlogger():
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)

    logfile = './log/ssclient.log'
    fh = logging.FileHandler(logfile)
    fh.setLevel(logging.WARNING)
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)

    formatter = logging.Formatter(
        "%(asctime)s - %(filename)s[line:%(lineno)d] - %(levelname)s: %(message)s"
    )
    fh.setFormatter(formatter)
    ch.setFormatter(formatter)

    logger.addHandler(fh)
    logger.addHandler(ch)
    logger.debug('logger set success')
    return logger


def send_all(sock, data):
    bytes_sent = 0
    while True:
        r = sock.send(data[bytes_sent:])
        if r == 0:
            return bytes_sent
        bytes_sent += r
        if bytes_sent == len(data):
            return bytes_sent


class ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True


class Socks5Server(socketserver.StreamRequestHandler):
    def handle_tcp(self, sock, remote):
        try:
            fdset = [sock, remote]
            while True:
                r, w, e = select.select(fdset, [], [])
                if sock in r:
                    data = sock.recv(4096)
                    if len(data) == 0:
                        break
                    result = send_all(remote, self.encrypt(data))
                    if result < len(data):
                        raise Exception('failed to send all data')

                if remote in r:
                    data = remote.recv(4096)
                    if len(data) == 0:
                        break
                    result = send_all(sock, self.decrypt(data))
                    if result < len(data):
                        raise Exception('failed to send all data')
        finally:
            sock.close()
            remote.close()

    def encrypt(self, data):
        return data

    def decrypt(self, data):
        return data

    def send_encrypt(self, sock, data):
        sock.send(self.encrypt(data))

    def handle(self):
        try:
            sock = self.request
            sock.recv(256)
            sock.send(b'\x05\x00')
            data = self.rfile.read(4)
            _VER = data[0]
            _CMD = data[1]
            _RSV = data[2]
            _ATYP = data[3]
            addr_to_send = data[3:4]
            if _CMD != 1:
                return
            if _ATYP == 1:
                addr_ip = self.rfile.read(4)
                addr = socket.inet_ntoa(addr_ip)
                addr_to_send += addr_ip
            elif _ATYP == 3:
                addr_len = self.rfile.read(1)
                addr = self.rfile.read(
                    int.from_bytes(addr_len, byteorder='big'))
                addr_to_send += addr_len + addr
            elif _ATYP == 4:
                addr_ip = self.rfile.read(16)
                addr = socket.inet_ntop(socket.AF_INET6, addr_ip)
                addr_to_send += addr_ip
            else:
                logger.warn('addr_type not support')
                return

            addr_port = self.rfile.read(2)
            addr_to_send += addr_port
            port = struct.unpack('>H', addr_port)
            try:
                reply = b'\x05\x00\x00\x01'
                reply += socket.inet_aton('0.0.0.0') + struct.pack('>H', 2222)
                self.wfile.write(reply)

                remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                remote.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                remote.connect((SERVER, REMOTE_PORT))

                self.send_encrypt(remote, addr_to_send)
                logger.info('connecting %s:%d' % (addr, port[0]))
            except socket.error as e:
                logger.error(e)
                return
            self.handle_tcp(sock, remote)
        except socket.error as e:
            logger.error(e)


if __name__ == '__main__':
    os.chdir(os.path.dirname(__file__) or '.')
    print('Shadowsocks v1.1')

    with open('config.json') as f:
        config = json.load(f)
    SERVER = config['server']
    REMOTE_PORT = config['server_port']
    PORT = config['local_port']
    KEY = config['password']

    optlist, args = getopt.getopt(sys.argv[1:], 's:p:k:l:')
    for key, value in optlist:
        if key == '-s':
            SERVER = value
        elif key == '-p':
            REMOTE_PORT = int(value)
        elif key == '-k':
            KEY = key
        elif key == '-l':
            PORT = int(value)

    logger = getlogger()

    try:
        server = ThreadingTCPServer(('', PORT), Socks5Server)
        logging.info("starting server at port %d ..." % PORT)
        server.serve_forever()
    except socket.error as e:
        logger.error(e)
    except KeyboardInterrupt:
        server.shutdown()
        sys.exit(0)
