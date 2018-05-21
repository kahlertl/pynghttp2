"""Asyncio HTTP/2 client and server sessions based on the :mod:`.nghttp2` Python
wrapper around the nghttp2 API.
"""
import asyncio
import logging
import io
import collections
from urllib.parse import urlparse
from ctypes import string_at

from . import nghttp2
from .messages import Request, Response, Direction
from .streams import make_stream_reader, read_data_source


logger = logging.getLogger(__name__)


recv_id = 0
send_id = 0

@nghttp2.on_frame_recv_callback
def on_frame_recv(session, frame, protocol):
    # print("recv", nghttp2.frame_type(frame[0].hd.type).name, f"stream_id={frame[0].hd.stream_id}")
    # if frame[0].hd.flags & nghttp2.flag.END_STREAM:
    #     print("     END_STREAM")

    # if frame[0].hd.type == nghttp2.frame_type.DATA:
    #     global recv_id
    #     print(f"    id={recv_id}")
    #     recv_id += 1

    # if frame[0].hd.type == nghttp2.frame_type.RST_STREAM:
    #     print(f"     error_code={nghttp2.error_code(frame[0].rst_stream.error_code).name}")

    # if frame[0].hd.type == nghttp2.frame_type.WINDOW_UPDATE:
    #     if frame[0].hd.stream_id == 0:
    #         print(f"    connection_window_size={protocol.session.get_remote_window_size()}")
    #     else:
    #         print(f"    stream_window_size={protocol.session.get_stream_remote_window_size(frame[0].hd.stream_id)}")

    if frame[0].hd.flags & nghttp2.flag.END_HEADERS:
        req = nghttp2.session_get_stream_user_data(session, frame[0].hd.stream_id)

        # For DATA and HEADERS frame, this callback may be called after
        # on_stream_close_callback. Check that stream is still alive.
        if not req:
            return 0

        protocol.headers_received(req)

    if frame[0].hd.flags & nghttp2.flag.END_STREAM:
        if frame[0].hd.type in [nghttp2.frame_type.HEADERS, nghttp2.frame_type.DATA]:
            req = nghttp2.session_get_stream_user_data(session, frame[0].hd.stream_id)

            if not req:
                return 0

            protocol.content_received(req)

    if frame[0].hd.type == nghttp2.frame_type.WINDOW_UPDATE:
        protocol.window_update_received(frame[0].hd.stream_id)

    elif frame[0].hd.type == nghttp2.frame_type.GOAWAY:
        protocol.goaway_received()

    return 0


@nghttp2.on_frame_send_callback
def on_frame_send(session, frame, protocol):
    # print("send", nghttp2.frame_type(frame[0].hd.type).name, f"stream_id={frame[0].hd.stream_id}")
    # if frame[0].hd.flags & nghttp2.flag.END_STREAM:
    #     print("     END_STREAM")

    # if frame[0].hd.type == nghttp2.frame_type.RST_STREAM:
    #     print(f"     error_code={nghttp2.error_code(frame[0].rst_stream.error_code).name}")

    # if frame[0].hd.type == nghttp2.frame_type.DATA:
    #     global send_id
    #     print(f"    id={send_id}")
    #     send_id += 1

    # if frame[0].hd.type == nghttp2.frame_type.DATA:
    #     print(f"    connection_window_size={protocol.session.get_remote_window_size()}")
    #     print(f"    stream_window_size={protocol.session.get_stream_remote_window_size(frame[0].hd.stream_id)}")

    if frame[0].hd.flags & nghttp2.flag.END_HEADERS:
        msg = nghttp2.session_get_stream_user_data(session, frame[0].hd.stream_id)
        protocol.headers_sent(msg)

    if frame[0].hd.flags & nghttp2.flag.END_STREAM:
        if frame[0].hd.type in [nghttp2.frame_type.HEADERS, nghttp2.frame_type.DATA]:
            msg = nghttp2.session_get_stream_user_data(session, frame[0].hd.stream_id)
            protocol.content_sent(msg)

    if frame[0].hd.type == nghttp2.frame_type.GOAWAY:
        protocol.goaway_sent()

    return 0


@nghttp2.on_header_callback
def on_header(session, frame, name, namelen, value, valuelen, flags, protocol):
    header = (
        string_at(name, size=namelen).decode(),
        string_at(value, size=valuelen).decode(),
    )
    msg = nghttp2.session_get_stream_user_data(session, frame[0].hd.stream_id)
    msg.headers.append(header)
    return 0


@nghttp2.on_data_chunk_recv_callback
def on_data_chunk_recv(session, flags, stream_id, data, length, protocol):
    msg = nghttp2.session_get_stream_user_data(session, stream_id)
    msg.content.feed_data(string_at(data, length))
    protocol.session.consume_connection(length)
    # protocol.session.consume_stream(stream_id, length)
    return 0


@nghttp2.on_stream_close_callback
def on_stream_close(session, stream_id, error_code, protocol):
    logger.debug("Stream %d closed (%s)", stream_id, nghttp2.error_code(error_code))
    msg = nghttp2.session_get_stream_user_data(session, stream_id)
    protocol.stream_closed(msg, error_code)
    return 0


@nghttp2.on_begin_headers_callback
def on_begin_headers(session, frame, protocol):
    stream_id = frame[0].hd.stream_id
    protocol.begin_headers(stream_id)
    return 0


class BaseHTTP2(asyncio.Protocol):

    def __init__(self, loop):
        super().__init__()
        self.loop = loop
        self.session = None
        self.transport = None
        self.peername = None

        # Dictionary mapping stream IDs to their associated stream data
        # keeping a reference to assigned stream data and prevent it from
        # garbage collection as long as the stream is still open. Otherwise it
        # could be possible for stream data Python objects to be garbage
        # collected and a callback would try to dereference the Python object
        # pointer leading to a SEGFAULT error.
        self._stream_data = {}

        self._paused = False
        self._connection_lost = False
        self._drain_waiter = None
        self._window_update_waiters = {}
        self._goaway_waiter = None

    def connection_made(self, transport):
        self.peername = transport.get_extra_info('peername')
        self.transport = transport

        self.establish_session()

        logger.debug("Send SETTINGS frame")
        self.flush()

    def data_received(self, data):
        logger.debug("Received %d bytes", len(data))

        read = self.session.mem_recv(data)
        if read < 0:
            self.session.terminate(nghttp2.error_code.INTERNAL_ERROR)
            self.flush()
            self.transport.close()
            return
        if read != len(data):
            logger.warn("Only %d bytes from %d processed", read, len(data))

        self.flush()

    def connection_lost(self, exc):
        logger.debug("Connection to %s:%d closed", *self.peername)
        self.session = None
        self._connection_lost = True

        for msg in self._stream_data.values():
            msg.set_exception(ConnectionResetError('Connection lost'))

        if not self._paused and self._drain_waiter is not None:
            waiter = self._drain_waiter
            self._drain_waiter = None
            if not waiter.done():
                if exc is None:
                    waiter.set_result(None)
                else:
                    waiter.set_exception(exc)

        if self._drain_waiter is not None:
            waiter = self._drain_waiter
            self._drain_waiter = None
            if not waiter.done():
                waiter.set_exception(ConnectionResetError('Connection lost'))

        for waiter in self._window_update_waiters.values():
            if not waiter.done():
                if exc is None:
                    waiter.set_result(None)
                else:
                    waiter.set_exception(exc)
        self._window_update_waiters.clear()

        if self._goaway_waiter is not None:
            waiter = self._goaway_waiter
            self._goaway_waiter = None
            if not waiter.done():
                if exc is None:
                    waiter.set_result(None)
                else:
                    waiter.set_exception(exc)

    def pause_writing(self):
        self._paused = True

    def resume_writing(self):
        self._paused = False

        waiter = self._drain_waiter
        if waiter is not None:
            self._drain_waiter = None
            if not waiter.done():
                waiter.set_result(None)

        self.flush()

    def flush(self):
        if self._connection_lost:
            return

        while self.session.want_write() and not self._paused:
            data = self.session.mem_send()
            if not data:
                break
            self.transport.write(data)

    async def wait_for_window_update(self, stream_id):
        assert stream_id not in self._window_update_waiters

        if self._connection_lost:
            raise ConnectionResetError('Connection lost')

        waiter = self.loop.create_future()
        self._window_update_waiters[stream_id] = waiter
        await waiter

    async def drain(self):
        if self._connection_lost:
            raise ConnectionResetError('Connection lost')

        if not self._paused:
            return

        assert self._drain_waiter is None
        waiter = self.loop.create_future()
        self._drain_waiter = waiter
        await self._drain_waiter

    def can_write_stream(self, stream_id):
        return (
            self.session.get_stream_remote_window_size(stream_id) > 0 and
            self.session.get_remote_window_size() > 0
        )

    async def terminate(self, error_code=nghttp2.error_code.NO_ERROR):
        if self._connection_lost:
            return

        assert self._goaway_waiter is None, 'Another coroutine is already waiting for the session to terminate'

        self.session.terminate(error_code)
        self.flush()

        waiter = self.loop.create_future()
        self._goaway_waiter = waiter
        try:
            await waiter
        finally:
            self._goaway_waiter = None

    def submit_request(self, resp, headers, provider):
        stream_id = self.session.submit_request(headers, provider, stream_data=resp)
        resp.stream_id = stream_id
        self._stream_data[stream_id] = resp

        # Write request to buffers
        self.flush()

        logger.debug("Submitted request on stream %d", stream_id)

    def submit_response(self, stream_id, headers, provider, resp):
        self.session.submit_response(stream_id, headers, provider)
        self.session.set_stream_user_data(stream_id, resp)
        self._stream_data[stream_id] = resp
        self.flush()

    def headers_sent(self, resp):
        resp.headers_sent()

    def content_sent(self, resp):
        resp.content_sent()

    def stream_closed(self, msg, error_code):
        msg.stream_closed()

        try:
            del self._stream_data[msg.stream_id]
        except KeyError:
            pass

    def window_update_received(self, stream_id):
        waiter = self._window_update_waiters.get(stream_id, None)
        if waiter:
            del self._window_update_waiters[stream_id]
            waiter.set_result(None)

    def goaway_sent(self):
        waiter = self._goaway_waiter
        if waiter is not None:
            self._goaway_waiter = None
            waiter.set_result(None)

    def goaway_received(self):
        self.transport.close()


class ServerProtocol(BaseHTTP2):

    def __init__(self, on_request_callback, loop):
        super().__init__(loop)
        self._on_request = on_request_callback

    def establish_session(self):
        logger.debug('Connection from %s:%d', *self.peername)
        options = nghttp2.Options(no_auto_window_update=True, no_http_messaging=True)
        self.session = nghttp2.Session(nghttp2.session_type.SERVER, {
            'on_frame_recv': on_frame_recv,
            'on_data_chunk_recv': on_data_chunk_recv,
            'on_frame_send': on_frame_send,
            'on_stream_close': on_stream_close,
            'on_begin_headers': on_begin_headers,
            'on_header': on_header,
        }, user_data=self, options=options)
        self.session.submit_settings([
            (nghttp2.settings_id.MAX_CONCURRENT_STREAMS, 10)
        ])

    def begin_headers(self, stream_id):
        req = Request(self, stream_id, loop=self.loop)
        self.session.set_stream_user_data(stream_id, req)
        self._stream_data[stream_id] = req

    def headers_received(self, req):
        req.headers_received()
        self._on_request(req)

    def content_received(self, req):
        req.content.feed_eof()


class ClientProtocol(BaseHTTP2):

    def establish_session(self):
        logger.debug('Connected to %s:%d', *self.peername)
        options = nghttp2.Options(no_auto_window_update=True, no_http_messaging=True)
        self.session = nghttp2.Session(nghttp2.session_type.CLIENT, {
            'on_frame_recv': on_frame_recv,
            'on_frame_send': on_frame_send,
            'on_data_chunk_recv': on_data_chunk_recv,
            'on_stream_close': on_stream_close,
            'on_begin_headers': on_begin_headers,
            'on_header': on_header,
        }, user_data=self, options=options)
        self.session.submit_settings([
            (nghttp2.settings_id.MAX_CONCURRENT_STREAMS, 10)
        ])

    def begin_headers(self, stream_id):
        pass

    def headers_received(self, resp):
        resp.headers_received()

    def content_received(self, resp):
        resp.content.feed_eof()


class ServerSession(object):

    def __init__(self, host, port, loop=None):
        self.host = host
        self.port = port
        self.loop = loop or asyncio.get_event_loop()
        self.server = None
        self._requests = collections.deque()
        self._waiter = None

    async def __aenter__(self):
        await self.start()
        return self

    async def __aexit__(self, *exc):
        self.close()
        await self.wait_closed()

    def __await__(self):
        return self._wait_for_request().__await__()

    async def _wait_for_request(self):
        # If no requests are available wait for at least one to arrive
        if not self._requests:
            assert self._waiter is None, 'Another coroutine is already waiting for new requests'
            logger.debug("Wait for request")
            waiter = self.loop.create_future()
            self._waiter = waiter
            try:
                await waiter
            finally:
                self._waiter = None

        return self._requests.popleft()

    def _received_request(self, req):
        self._requests.append(req)

        if self._waiter is not None:
            if not self._waiter.done():
                self._waiter.set_result(None)

    async def start(self):
        assert self.server is None, "ServerSession already started"
        self._requests.clear()
        self.server = await self.loop.create_server(
            lambda: ServerProtocol(self._received_request, self.loop),
            self.host, self.port)

    def close(self):
        self.server.close()

        waiter = self._waiter
        if waiter is not None and not waiter.done():
            self._waiter = None
            waiter.set_exception(ConnectionResetError("Server closed"))

    async def wait_closed(self):
        await self.server.wait_closed()
        self.server = None


class ClientSession(object):

    def __init__(self, host, port, loop=None):
        self.host = host
        self.port = port
        self.loop = loop or asyncio.get_event_loop()
        self.protocol = None

    async def __aenter__(self):
        await self.start()
        return self

    async def __aexit__(self, *exc):
        await self.terminate()

    async def start(self):
        assert self.protocol is None, "ClientSession already started"
        _, self.protocol = await self.loop.create_connection(
            lambda: ClientProtocol(self.loop),
            self.host, self.port)

    async def terminate(self):
        if self.protocol is None:
            return

        await self.protocol.terminate()

    def request(self, method, url, headers=None, data=None):
        _url = urlparse(url)
        _headers = [
            (':method', method),
            (':scheme', _url.scheme),
            (':authority', _url.netloc),
            (':path', _url.path or '*'),
        ]

        if headers:
            _headers.extend(headers)

        resp = Response(self.protocol,
            stream_id=None, direction=Direction.RECEIVING,
            loop=self.loop
        )

        if data is None:
            provider = None
        else:
            reader = make_stream_reader(data, _headers)
            provider = nghttp2.data_provider(
                source=nghttp2.data_source(ptr=reader),
                read_callback=read_data_source,
            )

        self.protocol.submit_request(resp, _headers, provider)

        return resp

    def get(self, url, headers=None):
        return self.request('GET', url, headers)

    def post(self, url, headers=None, data=None):
        return self.request('POST', url, headers, data)

