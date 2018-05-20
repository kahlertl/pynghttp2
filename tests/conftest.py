import pytest
from pynghttp2 import ServerSession, StreamReader
import traceback


async def send_stream(reader):
    chunk = bytearray(2 ** 16)
    start = bytearray(2 ** 16)
    start[:11] = b"Hello world"

    end = bytearray(2 ** 16)
    end[-13:] = b"Goodbye world"

    reader.feed_data(start)
    await reader.drain()

    for _ in range(2):
        reader.feed_data(chunk)
        await reader.drain()

    reader.feed_data(end)
    reader.feed_eof()
    await reader.drain()


class EchoServer(object):

    def __init__(self, loop):
        self.loop = loop
        self.session = None
        self.handlers = []

    async def __aenter__(self):
        self.session = ServerSession(host='localhost', port=64602, loop=self.loop)
        await self.session.start()
        self.handlers.append(self.loop.create_task(self._handle_requests()))
        return self.session

    async def pong(self, req):
        assert req.method == 'GET'
        await req.response(200, data=b"pong", headers=[('content-type', 'text/plain')])

    async def echo(self, req):
        assert req.method == 'POST'
        msg = await req.read()
        await req.response(200, data=msg)

    async def stream(self, req):
        reader = StreamReader()
        resp = req.response(200, headers=[('content-length', str(4 * 2 ** 16))], data=reader)
        # resp = req.response(200, data=reader)
        streamer = self.loop.create_task(send_stream(reader))

        try:
            await resp
            assert streamer.done()
        finally:
            streamer.cancel()

    async def not_found(self, req):
        return req.response(404)

    async def _handle_requests(self):
        handlers = {
            '/ping': self.pong,
            '/echo': self.echo,
            '/stream': self.stream,
        }

        async def wrapper(handler):
            try:
                await handler
            except ConnectionResetError:
                print("Connection closed")
            except Exception as err:
                traceback.print_exc()

        while True:
            req = await self.session
            handler = handlers.get(req.path, self.not_found)(req)
            task = self.loop.create_task(wrapper(handler))
            task.add_done_callback(lambda t: self.handlers.remove(t))
            self.handlers.append(task)

    async def __aexit__(self, *exc):
        for handler in self.handlers:
            handler.cancel()
        self.handlers = []

        self.session.close()
        await self.session.wait_closed()
        self.session = None


@pytest.fixture
def echo_server(event_loop):
    yield EchoServer(loop=event_loop)
