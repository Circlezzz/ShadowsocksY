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
                    result = send_all(remote, self.decrypt(data))
                    if result < len(data):
                        raise Exception('failed to send all data')

                if remote in r:
                    data = remote.recv(4096)
                    if len(data) <= 0:
                        break
                    result = send_all(sock, self.encrypt(data))
                    if result < len(data):
                        raise Exception('failed to send all data')
        finally:
            sock.close()
            remote.close()

    def encrypt(self, data):
        return data

    def decrypt(self, data):
        return data

    def handle(self):
        try:
            sock = self.connection
            addrtype = int.from_bytes(
                self.decrypt(sock.recv(1)), byteorder='big')
            if addrtype == 1:
                addr = socket.inet_ntoa(self.decrypt(self.rfile.read(4)))
            elif addrtype == 3:
                addr = self.decrypt(
                    self.rfile.read(
                        int.from_bytes(self.decrypt(sock.recv(1)))))
            elif addrtype == 4:
                addr = socket.inet_ntop(socket.AF_INET6,
                                        self.decrypt(self.rfile.read(16)))
            else:
                logging.warn('addr_type not support')
                return
            port = struct.unpack('>H', self.decrypt(self.rfile.read(2)))
            try:
                logger.info('connecting %s:%d' % (addr, port[0]))
                remote = socket.create_connection((addr, port[0]))
            except socket.error as e:
                logger.error(e)
                return
            self.handle_tcp(sock, remote)
        except socket.error as e:
            logger.error(e)


if __name__ == '__main__':
    os.chdir(os.path.dirname(__file__))
    print('shadowsocks v1.1')

    with open('config.json') as f:
        config = json.load(f)

    SERVER = config['server']
    PORT = config['server_port']
    KEY = config['password']

    optlist, args = getopt.getopt(sys.argv[1:], 'p:k:')
    for key, value in optlist:
        if key == '-p':
            PORT = int(value)
        elif key == '-k':
            KEY = value

    logger = getlogger()
    try:
        server = ThreadingTCPServer(('', PORT), Socks5Server)
        logger.info('starting server at port %d ...' % PORT)
        server.serve_forever()
    except socket.error as e:
        logger.error(e)