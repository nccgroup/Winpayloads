import asyncio
import ssl
import threading


class StartAsync(threading.Thread):
    def __init__(self, loop, port=5555):
        threading.Thread.__init__(self)
        self.loop = loop
        self.port = port
        self.server = Server()
        self.setDaemon(True)

    def run(self):
        self.coro = asyncio.start_server(self.server.client_connect,
                                         '0.0.0.0',
                                         port=self.port,
                                         loop=self.loop
                                         )
        self.listener = self.loop.run_until_complete(self.coro)
        self.loop.run_forever()

    def close(self):
        self.listener.close()
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.join()
        print('Server Stopped')


class Client():
    def __init__(self, writer, reader):
        self.writer = writer
        self.reader = reader
        self.in_buffer = []
        self.out_buffer = []

    async def client_task(self):
        while True:
            data = await self.reader.read(8000)
            if data == b'':
                print('Received EOF. Client disconnected.')
                return
            else:
                self.in_buffer.append(data)
                await self.writer.drain()


class Server():
    def __init__(self):
        self.clients = {}
        self.clientnumber = 0

    def client_connect(self, client_reader, client_writer):
        addr = client_writer.get_extra_info('peername')
        print('Client connected: {}'.format(addr))

        client = Client(client_writer, client_reader)
        task = asyncio.ensure_future(client.client_task())
        self.clientnumber += 1
        self.clients[self.clientnumber] = client


if __name__ == '__main__':
    print("starting up..")
    loop = asyncio.get_event_loop()
    listener = StartAsync(loop=loop)
    listener.start()
    try:
        while True:
            comm = input(': ')
            if comm == 'print':
                if a.server.clients[1].in_buffer:
                    print(a.server.clients[1].in_buffer.pop())
            if 'send' in comm:
                a.server.clients[1].out_buffer.append(comm.split(' ')[1])
    except KeyboardInterrupt:
        listener.close()
