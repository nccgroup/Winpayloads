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

    def stop(self):
        self.server.close()
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.join()
        print('Server Stopped')


class Client():
    def __init__(self, writer, reader, addr):
        self.addr = addr
        self.writer = writer
        self.reader = reader
        self.in_buffer = []
        self.out_buffer = []

    async def receive(self):
        print("started reading")
        while True:
            data = await self.reader.read(8000)
            print("read data")
            if data == b'':
                self.close_client()
            else:
                self.in_buffer.append(data.decode())

    async def send(self):
        print("started sending")
        while True:
            if len(self.out_buffer) > 0:
                data = self.out_buffer.pop()
                print("sent data")
                self.writer.write(data.encode())
                await self.writer.drain()
            await asyncio.sleep(0.2)

    def close_client(self):
        self.writer.close()
        print("Closing Client {}".format(self.addr))


class Server():
    def __init__(self):
        self.clients = {}
        self.clientnumber = 0

    async def client_connect(self, client_reader, client_writer):
        addr = client_writer.get_extra_info('peername')
        print('Client connected: {}'.format(addr))

        client = Client(client_writer, client_reader, addr)
        self.clientnumber += 1
        self.clients[self.clientnumber] = client
        await asyncio.gather(
            client.send(),
            client.receive()

        )

    def close(self):
        for client in self.clients.values():
            client.close_client()


if __name__ == '__main__':
    print("starting up..")
    loop = asyncio.get_event_loop()
    listener = StartAsync(loop=loop)
    listener.start()
    try:
        while True:
            comm = input(': ')
            if comm == 'print':
                if listener.server.clients[1].in_buffer:
                    print(listener.server.clients[1].in_buffer.pop())
            if 'send' in comm:
                listener.server.clients[1].out_buffer.append(comm.split()[1])
    except KeyboardInterrupt:
        listener.stop()
