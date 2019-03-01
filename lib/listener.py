from stager import *
import threading

amap = {}

class StartAsync(threading.Thread):
    def __init__(self, map=amap):
        threading.Thread.__init__(self)
        self.setDaemon(True)
        self.map = amap
        self.started = False

    def run(self):
        while True:
            if self.started:
                asyncore.loop(timeout=0.5, map=self.map)
                self.started = False
            else:
                while not self.map:
                    time.sleep(0.5)
                self.started = True


class Handler(asyncore.dispatcher):
    def __init__(self, clientconn, server, map):
        asyncore.dispatcher.__init__(self, sock=clientconn, map=amap)
        self.server = server
        self.in_buffer = []
        self.out_buffer = []
        self.user_name = ''
        self.is_admin = ''
        return

    def handle_close(self):
        print t.bold_red + "Client %s Connection Killed"% self.server.get_clientnumber() + t.normal
        self.close()

    def readable(self):
        return True

    def handle_read(self):
        data = self.recv(8000)
        if data:
            self.in_buffer.append(data)
            if '[#check#]' in data:
                self.user_name = "User:" + data.split(':')[0].replace('\x00','').replace('[#check#]','')
                self.is_admin = "Admin:" + data.split(':')[1].replace('\x00','').replace('[#check#]','')
                from menu import clientMenuOptions
                clientMenuOptions[self.server.get_clientnumber()] =  {'payloadchoice': None, 'payload':str(self.getpeername()[0]) + ":" + str(self.getpeername()[1]), 'extrawork': interactShell, 'params': (self.server.get_clientnumber()), 'availablemodules':{self.user_name: '', self.is_admin: ''}}
                self.in_buffer = []

    def writable(self):
        return len(self.out_buffer) > 0

    def handle_write(self):
        sent = self.send(self.out_buffer.pop())

class Server(asyncore.dispatcher):
    want_read = want_write = True
    def __init__(self, host, port, bindsocket=False, relay=False, map=amap):
        asyncore.dispatcher.__init__(self, map=amap)
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.set_reuse_addr()
        self.handlers = {}
        self.clientnumber = 0
        self.bindsocket = bindsocket
        self.relay = relay
        self.map = amap

        if self.bindsocket:
            self.bind((host, port))
            self.listen(30)
        elif self.relay:
            self.bind((host, port))
            self.listen(1)
        else:
            self.connect((host, port))


    def writable(self):
        return self.want_write

    def readable(self):
        return self.want_read

    def handle_connect(self):
        self.socket = ssl.wrap_socket(self.socket, ssl_version=ssl.PROTOCOL_TLSv1, ciphers='AES256', do_handshake_on_connect=False)
        print '[*] Connection to %s:%s'%(self.socket.getpeername())

    def _handshake(self):
        try:
            self.socket.do_handshake()
        except ssl.SSLError, err:
            self.want_read = self.want_write = False
            if err.args[0] == ssl.SSL_ERROR_WANT_READ:
                self.want_read = True
            elif err.args[0] == ssl.SSL_ERROR_WANT_WRITE:
                self.want_write = True
            else:
                raise
        else:
            self.clientnumber += 1
            handler = Handler(self.socket, self, map=self.map)
            self.handlers[self.clientnumber] = handler

    def handle_accept(self):
        if self.bindsocket:
            self.socket = ssl.wrap_socket(self.socket, ssl_version=ssl.PROTOCOL_TLSv1, ciphers='AES256', server_side=True, certfile='server.crt', keyfile='server.key')
        clientconn, address = self.accept()
        if clientconn:
            print '[*] Connection from %s:%s'%(address)
            self.clientnumber += 1
            handler = Handler(clientconn, self, map=self.map)
            self.handlers[self.clientnumber] = handler


    def get_clientnumber(self):
        return str(self.clientnumber)

    handle_read = handle_write = _handshake
