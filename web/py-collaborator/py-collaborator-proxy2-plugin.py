#!/usr/bin/python3

import re
import sys
import json
import string
import random
import datetime    
import socket
import requests
import functools
from urlparse import urljoin, urlparse
from threading import Lock
from Database import Database
from proxylogger import ProxyLogger
from threading import Thread
from time import sleep

VERSION = '0.1'

# Must point to JSON file containing configuration mentioned in `config` dictionary below.
# One can either supply that configuration file, or let the below variable empty and fill the `config`
# dictionary instead.
CONFIGURATION_FILE = 'config.json'

config = {
    # The server hostname where affected systems shall pingback.
    'pingback-host': '',
    'server-remote-addr': '',

    'mysql-host': '',
    'mysql-user': '',
    'mysql-pass': '',
    'mysql-database': '',
}

append_headers = (
    'X-Forwarded-For',
    'Referer',
    'True-Client-IP',
    'X-Originating-IP',
    'X-Client-IP',
    'Client-IP',
    'X-Real-IP',
    'Contact',
    'Forwarded',
    'CF-Connecting_IP',
    'X-WAP-Profile'
)

visited_hosts = set()
add_host_lock = Lock()
database_lock = Lock()

CONNECTION_TIMEOUT = 4.0
CHUNK_SIZE = 512

def generateRandomId():
    randomized = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(50))
    return f"xxx{randomized}yyy"

# note that this decorator ignores **kwargs
def memoize(obj):
    cache = obj.cache = {}

    @functools.wraps(obj)
    def memoizer(*args, **kwargs):
        if args not in cache:
            cache[args] = obj(*args, **kwargs)
        return cache[args]
    return memoizer


class SendRawHttpRequest:
    def __init__(self, proxyOptions, logger):
        self.sock = None
        self.logger = logger
        self.proxyOptions = proxyOptions

    def connect(self, host, port, _ssl, timeout):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            if _ssl:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.options |= ssl.OP_ALL
                context.verify_mode = ssl.CERT_NONE

                self.sock = context.wrap_socket(sock)
            else:
                self.sock = sock

            self.sock.settimeout(timeout)
            self.sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
            self.sock.connect((host, port))
            self.logger.dbg(f'Connected with {host}')
            return True

        except Exception as e:
            self.logger.err(f'[!] Could not connect with {host}:{port}!')
            if self.proxyOptions['debug']:
                raise
            return False

    def close(self):
        if self.sock:
            self.sock.shutdown(socket.SHUT_RDWR)
            self.sock.close()

        self.sock = None
        self.raw_socket = None
        self.ssl_socket = None

    def receiveAll(self, chunk_size=CHUNK_SIZE):
        chunks = []
        while True:
            try:
                chunk = resp = self.sock.recv(int(chunk_size))
            except:
                if chunk: 
                    chunks.append(chunk)
                break

            if chunk:
                chunks.append(chunk)
            else:
                break

        return ''.join(chunks)

    def send(self, host, port, ssl, data, timeout = CONNECTION_TIMEOUT):
        if not self.connect(host, port, ssl, timeout):
            return False

        self.sock.send(data)
        resp = self.receiveAll()
        self.close()
        return resp.decode(errors='ignore')

class ProxyHandler:    
    method = ''
    request = None
    requestBody = None

    def __init__(self, logger, params, proxyOptions = None):
        global config

        self.databaseInstance = self.connection = None
        self.logger = logger
        self.params = params
        self.proxyOptions = proxyOptions

        if CONFIGURATION_FILE:
            config.update(json.loads(open(CONFIGURATION_FILE).read()))

        config['debug'] = proxyOptions['debug']

        self.logger.info('Initializing Pingback proxy2 plugin.')

        self.connection = None
        self.createConnection()

    def createConnection(self):
        self.databaseInstance = Database()

        self.logger.info(
            f"Connecting to MySQL database: {config['mysql-user']}@{config['mysql-host']} ..."
        )
        self.connection = self.databaseInstance.connection(  config['mysql-host'], 
                                                        config['mysql-user'], 
                                                        config['mysql-pass'],
                                                        config['mysql-database'])

        if not self.connection:
            self.logger.err('Could not connect to the MySQL database! ' \
                    'Please configure inner `MySQL` variables such as Host, User, Password.')
            sys.exit(1)

        self.logger.info('Connected.')

    def executeSql(self, query, params = None):
        try:
            assert self.connection
            database_lock.acquire()
            out = (
                self.databaseInstance.query(query, params=params)
                if params
                else self.databaseInstance.query(query)
            )
            database_lock.release()
            return out if out else []
        except Exception as e:
            self.logger.err(
                f'SQL query ("{query}", params: {str(params)}) has failed: {str(e)}'
            )
            database_lock.release()
            if self.proxyOptions['debug']:
                raise
            return []

    @staticmethod
    @memoize
    def requestToString(request):
        headers = '\r\n'.join([f'{k}: {v}' for k, v in request.headers.items()])
        return f'{request.command} {request.path} {request.request_version}\r\n{headers}'

    @staticmethod
    def getPingbackUrl(request):
        #guid = str(uuid.uuid4())
        guid = generateRandomId()
        url = f"http://{guid}.{config['pingback-host']}/"
        return (url, guid)

    def saveRequestForCorrelation(self, request, pingback, uuid, where):
        query = 'INSERT INTO requests(id, sent, uuid, desthost, pingback, whereput, request) VALUES(%s, %s, %s, %s, %s, %s, %s)'
        generatedRequest = ProxyHandler.requestToString(self.request)
        desthost = self.request.headers['Host']
        values = ('0', datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'), uuid, desthost, pingback, where, generatedRequest)
        self.executeSql(query, values)

    @staticmethod
    def sendRawRequest(request, requestData, proxyOptions, logger):
        raw = SendRawHttpRequest(proxyOptions, logger)
        port = 80 if request.scheme == 'http' else 443
        return raw.send(request.headers['Host'], port, request.scheme == 'https', requestData)

    def hostOverriding(self):
        (pingback, uuid) = ProxyHandler.getPingbackUrl(self.request)
        requestData = (
            f'GET {pingback} HTTP/1.1\r\n'
            + f"Host: {self.request.headers['Host']}\r\n"
        )
        requestData+= 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36\r\n'
        requestData+= 'Accept: */*\r\n'
        requestData+= 'Connection: close\r\n'

        self.saveRequestForCorrelation(
            self.request,
            pingback,
            uuid,
            f"Overridden Host header ({self.request.headers['Host']} -> GET /{pingback} )",
        )
        ProxyHandler.sendRawRequest(self.request, requestData, self.proxyOptions, self.logger)
        self.logger.dbg(
            f'(2) Re-sending host overriding request ({self.request.path} -> {pingback})'
        )

    def hostAtManipulation(self):
        (pingback, uuid) = ProxyHandler.getPingbackUrl(self.request)
        url = urljoin(
            f'{self.request.scheme}://',
            self.request.headers['Host'],
            self.request.path,
        )
        parsed = urlparse(pingback)

        requestData = (
            f'GET {pingback} HTTP/1.1\r\n'
            + f"Host: {self.request.headers['Host']}@{parsed.netloc}\r\n"
        )
        requestData+= 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36\r\n'
        requestData+= 'Accept: */*\r\n'
        requestData+= 'Connection: close\r\n'

        self.saveRequestForCorrelation(
            self.request,
            pingback,
            uuid,
            f"Host header manipulation ({self.request.headers['Host']} -> {self.request.headers['Host']}@{parsed.netloc})",
        )
        ProxyHandler.sendRawRequest(self.request, requestData, self.proxyOptions, self.logger)
        self.logger.dbg(
            f"(3) Re-sending host header @ manipulated request ({self.request.headers['Host']} -> {self.request.headers['Host']}@{parsed.netloc})"
        )

    def sendMisroutedRequests(self):
        (pingback, uuid) = ProxyHandler.getPingbackUrl(self.request)
        url = urljoin(
            f'{self.request.scheme}://',
            self.request.headers['Host'],
            self.request.path,
        )
        url = url.replace(':///', "://")
        parsed = urlparse(pingback)

        self.saveRequestForCorrelation(
            self.request,
            pingback,
            uuid,
            f"Hijacked Host header ({self.request.headers['Host']} -> {parsed.netloc})",
        )
        self.logger.dbg(
            f"ok(1) Re-sending misrouted request with hijacked Host header ({self.request.headers['Host']} -> {parsed.netloc})"
        )

        try:
            self.logger.dbg(f'GET {url}')
            requests.get(url, headers = {'Host' : parsed.netloc})
        except Exception as e:
            self.logger.err(f'Could not issue request to ({url}): {str(e)}')
            if self.proxyOptions['debug']:
                raise

        self.hostOverriding()
        self.hostAtManipulation()

    @memoize
    def checkIfAlreadyManipulated(self, host):
        query = f"""SELECT desthost FROM {config['mysql-database']}.requests WHERE desthost = "{host}\""""

        rows = self.executeSql(query)
        if rows == False: return rows
        for row in rows:
            if self.request.headers['Host'] in row['desthost']:
                self.logger.dbg(f"Host ({row['desthost']}) already was lured for pingback.")
                return True

        self.logger.dbg(
            f"Host ({self.request.headers['Host']}) was not yet lured for pingback."
        )
        return False

    def request_handler(self, req, req_body):
        global visited_hosts
        self.request = req
        self.requestBody = req_body

        self.request.scheme = self.request.path.split(':')[0].upper()

        allowed_letters = string.ascii_lowercase + string.digits + '-_.'
        host = filter(lambda x: x in allowed_letters, self.request.headers['Host'])

        if (host not in visited_hosts) and (not self.checkIfAlreadyManipulated(host)):
            add_host_lock.acquire()
            visited_hosts.add(host)
            add_host_lock.release()

            for header in append_headers:   
                (pingback, uuid) = ProxyHandler.getPingbackUrl(self.request)
                self.request.headers[header] = pingback
                if 'IP' in header:
                    self.request.headers[header] = f"{uuid}.{config['pingback-host']}"
                self.saveRequestForCorrelation(pingback, header, uuid, f'Header: {header}')

            self.sendMisroutedRequests()
            self.logger.info(f'Injected pingbacks for host ({host}).', forced = True)


        return self.requestBody

    def response_handler(self, req, req_body, res, res_body):
        pass
    
