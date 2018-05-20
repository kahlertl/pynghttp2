import enum
try:
    import simplejson as json
except ImportError:
    import json
from .streams import StreamReader, make_stream_reader, read_data_source
from . import nghttp2


class StreamClosedError(ConnectionError):
    
    def __init__(self, stream_id=None):
        if stream_id is not None:
            super().__init__("Stream {} was closed".format(stream_id))
        else:
            super().__init__("Stream was closed")


class Direction(enum.IntEnum):
    RECEIVING = 0
    SENDING = 1


class HTTP2Message(object):

    def __init__(self, protocol, stream_id, direction, content=None, loop=None):
        self.headers = []
        if content is None:
            self.content = StreamReader()
        else:
            self.content = content
        self.content.set_protocol(protocol, stream_id)

        # Session handling
        self._stream_id = stream_id
        self.protocol = protocol
        self._loop = loop or asyncio.get_event_loop()
        self._direction = direction
        self._exception = None

        # Receiving messages
        self._content = None
        self._headers_waiter = None
        self._headers_received = False

        # Sending message
        self._sent_waiter = None
        self._headers_sent = False
        self._content_sent = False

    @property
    def stream_id(self):
        return self._stream_id

    @stream_id.setter
    def stream_id(self, stream_id):
        self._stream_id = stream_id
        self.content._stream_id = stream_id

    @property
    def content_length(self):
        for name, value in self.headers:
            if name == 'content-length':
                return int(value)
        return None

    @property
    def content_type(self):
        for name, value in self.headers:
            if name == 'content-type':
                return value
        return None

    def set_exception(self, exc):
        self._exception = exc
        self.content.set_exception(exc)

        waiter = self._headers_waiter
        if waiter is not None and not waiter.done():
            self._headers_waiter = None
            waiter.set_exception(exc)

        waiter = self._sent_waiter
        if waiter is not None and not waiter.done():
            self._sent_waiter = None
            waiter.set_exception(exc)

    async def read(self):
        assert self._direction == Direction.RECEIVING, "Cannot read from sending message"
    
        if self._content is None:
            await self._wait_for_headers()
            self._content = await self.content.read()

        return self._content

    async def text(self):
        data = await self.read()
        return data.decode()

    async def json(self):
        data = await self.read()
        try:
            return json.loads(data)
        except json.JSONDecodeError:
            return None

    def headers_received(self):
        assert self._direction == Direction.RECEIVING, "Cannot receive headers for sending message"
        assert self._headers_received == False, "HEADERS already received"
        self._headers_received = True

        waiter = self._headers_waiter
        if waiter is not None:
            self._headers_waiter = None
            if not waiter.done():
                waiter.set_result(None)

    def headers_sent(self):
        assert not self._headers_sent, "HEADERS already sent"
        self._headers_sent = True

        if self._content_sent and self._sent_waiter is not None:
            self._sent_waiter.set_result(None)

    def content_sent(self):
        assert not self._content_sent, "Content already sent"
        self._content_sent = True

        if self._sent_waiter is not None:
            assert self._headers_sent, "HEADERS still pending"
            self._sent_waiter.set_result(None)

    def stream_closed(self):
        self.set_exception(StreamClosedError(self._stream_id))

    def __await__(self):
        if self._direction == Direction.RECEIVING:
            return self._wait_for_headers().__await__()
        else:
            return self._wait_sent().__await__()

    async def _wait_for_headers(self):
        if self._headers_received:
            return

        if self._exception:
            raise self._exception

        assert self._headers_waiter is None, 'Another coroutine is already waiting for headers'

        waiter = self._loop.create_future()
        self._headers_waiter = waiter
        try:
            self.protocol.flush()
            await waiter
        finally:
            self._headers_waiter = None

    async def _wait_sent(self):
        if self._headers_sent and self._content_sent:
            return

        if self._exception:
            raise self._exception

        assert self._sent_waiter is None

        waiter = self._loop.create_future()
        self._sent_waiter = waiter
        try:
            self.protocol.flush()
            await waiter
        finally:
            self._sent_waiter = None


class Request(HTTP2Message):

    def __init__(self, protocol, stream_id, loop):
        super().__init__(protocol, stream_id, Direction.RECEIVING, loop=loop)

    @property
    def path(self):
        for name, value in self.headers:
            if name == ':path':
                return value
        return None

    @property
    def method(self):
        for name, value in self.headers:
            if name == ':method':
                return value.upper()
        return None

    def __repr__(self):
        return "<http2.Request {} {}>".format(
            self.method,
            self.path,
        )

    def response(self, status, data=None, headers=None):
        _headers = [
            (':status', str(status)),
        ]
        if headers:
            _headers.extend(headers)

        reader = make_stream_reader(data, _headers)
        resp = Response(self.protocol, self._stream_id, Direction.SENDING,
                        content=reader, loop=self._loop)

        if data is None:
            provider = None
            resp.content_sent()
        else:
            provider = nghttp2.data_provider(
                source=nghttp2.data_source(ptr=reader),
                read_callback=read_data_source,
            )

        self.protocol.submit_response(self._stream_id, _headers, provider, resp)

        return resp


class Response(HTTP2Message):

    @property
    def status(self):
        for name, value in self.headers:
            if name == ':status':
                return int(value)
        return None

    def __repr__(self):
        if self.status and self.content_type:
            return "<http2.Response {} {}>".format(
                self.status,
                self.content_type,
            )
        elif self.status:
            return "<http2.Response {}>".format(
                self.status,
            )
        else:
            return "<http2.Response>"