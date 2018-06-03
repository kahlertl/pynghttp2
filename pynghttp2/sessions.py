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
from .streams import read_data_source


logger = logging.getLogger(__name__)


recv_id = 0
send_id = 0

@nghttp2.on_frame_recv_callback
def on_frame_recv(session, frame, protocol):
    stream_id = frame[0].hd.stream_id
    frame_type = frame[0].hd.type

    # print(protocol.__class__.__name__, "recv", nghttp2.frame_type(frame_type).name, f"stream_id={stream_id}")
    # if frame[0].hd.flags & nghttp2.flag.END_STREAM:
    #     print(protocol.__class__.__name__, "     END_STREAM")
    # if frame[0].hd.flags & nghttp2.flag.ACK:
    #     print(protocol.__class__.__name__, "     ACK")

    # if frame_type == nghttp2.frame_type.RST_STREAM:
    #     print(protocol.__class__.__name__, f"     error_code={nghttp2.error_code(frame[0].rst_stream.error_code).name}")

    # if frame_type == nghttp2.frame_type.WINDOW_UPDATE:
    #     if stream_id == 0:
    #         print(protocol.__class__.__name__, f"    connection_window_size={protocol.session.get_remote_window_size()}")
    #     else:
    #         print(protocol.__class__.__name__, f"    stream_window_size={protocol.session.get_stream_remote_window_size(stream_id)}")

    if frame[0].hd.flags & nghttp2.flag.END_HEADERS:
        protocol.headers_received(stream_id)

    if frame[0].hd.flags & nghttp2.flag.END_STREAM:
        if frame_type in [nghttp2.frame_type.HEADERS, nghttp2.frame_type.DATA]:
            protocol.content_received(stream_id)

    if frame_type == nghttp2.frame_type.WINDOW_UPDATE:
        protocol.window_update_received(stream_id)

    elif frame_type == nghttp2.frame_type.GOAWAY:
        protocol.goaway_received(nghttp2.error_code(frame[0].goaway.error_code))

    elif frame_type == nghttp2.frame_type.SETTINGS:
        protocol.settings_updated()

    return 0


@nghttp2.on_frame_send_callback
def on_frame_send(session, frame, protocol):
    stream_id = frame[0].hd.stream_id
    frame_type = frame[0].hd.type

    # print(protocol.__class__.__name__, "send", nghttp2.frame_type(frame_type).name, f"stream_id={stream_id}")
    # if frame[0].hd.flags & nghttp2.flag.END_STREAM:
    #     print(protocol.__class__.__name__, "     END_STREAM")

    # if frame_type == nghttp2.frame_type.RST_STREAM:
    #     print(protocol.__class__.__name__, f"     error_code={nghttp2.error_code(frame[0].rst_stream.error_code).name}")

    # if frame_type == nghttp2.frame_type.DATA:
    #     print(protocol.__class__.__name__, f"    connection_window_size={protocol.session.get_remote_window_size()}")
    #     print(protocol.__class__.__name__, f"    stream_window_size={protocol.session.get_stream_remote_window_size(stream_id)}")

    if frame[0].hd.flags & nghttp2.flag.END_HEADERS:
        protocol.headers_sent(stream_id)

    if frame[0].hd.flags & nghttp2.flag.END_STREAM:
        if frame_type in [nghttp2.frame_type.HEADERS, nghttp2.frame_type.DATA]:
            protocol.content_sent(stream_id)

    elif frame_type == nghttp2.frame_type.GOAWAY:
        protocol.goaway_sent(nghttp2.error_code(frame[0].goaway.error_code))

    return 0


@nghttp2.on_header_callback
def on_header(session, frame, name, namelen, value, valuelen, flags, protocol):
    header = (
        string_at(name, size=namelen).decode(),
        string_at(value, size=valuelen).decode(),
    )
    # msg = nghttp2.session_get_stream_user_data(session, frame[0].hd.stream_id)
    # msg.headers.append(header)
    protocol.on_header(frame[0].hd.stream_id, header)
    return 0


@nghttp2.on_data_chunk_recv_callback
def on_data_chunk_recv(session, flags, stream_id, data, length, protocol):
    protocol.on_data_chunk_recv(stream_id, string_at(data, length))
    # msg = nghttp2.session_get_stream_user_data(session, stream_id)
    # msg.content.feed_data(string_at(data, length))
    # protocol.session.consume_connection(length)
    # protocol.session.consume_stream(stream_id, length)
    return 0


@nghttp2.on_stream_close_callback
def on_stream_close(session, stream_id, error_code, protocol):
    error = nghttp2.error_code(error_code)
    logger.debug("Stream %d closed (%s)", stream_id, error.name)
    protocol.stream_closed(stream_id, error)
    return 0


@nghttp2.on_begin_headers_callback
def on_begin_headers(session, frame, protocol):
    stream_id = frame[0].hd.stream_id
    protocol.begin_headers(stream_id)
    return 0


class BaseHTTP2(asyncio.Protocol):

    def __init__(self, settings, loop):
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
        
        # Wait for the first SETTINGS frame before submitting any new stream
        self._max_streams = 0

        # A queue with pending (Response, Request) pairs. We use a FIFO queue to
        # only open up as much new streams as allowed.
        self._pending = collections.deque()

        self._settings = settings
        self._writing_paused = False
        self._connection_lost = False
        self._drain_waiter = None
        self._window_update_waiters = {}
        self._goaway_waiter = None
        self._goaway_error = None

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

        if self._goaway_error is None:
            self._goaway_error = ConnectionResetError('Connection lost')

        reset_error = exc or self._goaway_error

        for incoming, outgoing in self._stream_data.values():
            if incoming is not None:
                incoming.set_exception(reset_error)
            if outgoing is not None:
                outgoing.set_exception(reset_error)

        for resp, req in self._pending:
            req.set_exception(self._goaway_error)
            resp.set_exception(self._goaway_error)

        if not self._writing_paused and self._drain_waiter is not None:
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
                waiter.set_exception(reset_error)

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
        self._writing_paused = True

    def resume_writing(self):
        self._writing_paused = False

        waiter = self._drain_waiter
        if waiter is not None:
            self._drain_waiter = None
            if not waiter.done():
                waiter.set_result(None)

        self.flush()

    def flush(self):
        if self._connection_lost:
            return

        # Submit as much pending requests as allowed by the minimum
        # SETTINGS_MAX_CONCURRENT_STREAMS of local and remote endpoint
        while self._pending and len(self._stream_data) < self._max_streams:
            resp, req = self._pending.pop()

            if req.content.at_eof():
                provider = None
            else:
                provider = nghttp2.data_provider(
                    source=nghttp2.data_source(ptr=req.content),
                    read_callback=read_data_source,
                )
            stream_id = self.session.submit_request(req.headers, provider)
            req.stream_id = stream_id
            resp.stream_id = stream_id
            self._stream_data[stream_id] = resp, req

            logger.debug("Submitted request on stream %d", stream_id)

        while self.session.want_write() and not self._writing_paused:
            data = self.session.mem_send()
            if not data:
                break
            self.transport.write(data)

    async def wait_for_window_update(self, stream_id):
        assert stream_id not in self._window_update_waiters

        if self._connection_lost:
            raise self._goaway_error

        waiter = self.loop.create_future()
        self._window_update_waiters[stream_id] = waiter
        await waiter

    async def drain(self):
        if self._connection_lost:
            raise self._goaway_error

        if not self._writing_paused:
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
        await waiter

    def submit_response(self, stream_id, resp):
        if self._connection_lost:
            raise self._goaway_error

        if resp.content.at_eof():
            provider = None
        else:
            provider = nghttp2.data_provider(
                source=nghttp2.data_source(ptr=resp.content),
                read_callback=read_data_source,
            )
        self.session.submit_response(stream_id, resp.headers, provider)
        req, _ = self._stream_data[stream_id]
        self._stream_data[stream_id] = (req, resp)
        self.flush()

    def settings_updated(self):
        logger.debug("SETTINGS updated")
        self._max_streams = min(
            self.session.get_local_settings(nghttp2.settings_id.MAX_CONCURRENT_STREAMS),
            self.session.get_remote_settings(nghttp2.settings_id.MAX_CONCURRENT_STREAMS),
        )

    def on_header(self, stream_id, header):
        incoming, _ = self._stream_data[stream_id]
        incoming.headers.append(header)

    def headers_sent(self, stream_id):
        _, outgoing = self._stream_data[stream_id]
        outgoing.headers_sent()

    def on_data_chunk_recv(self, stream_id, chunk):
        incoming, _ = self._stream_data[stream_id]
        incoming.content.feed_data(chunk)
        self.session.consume_connection(len(chunk))

    def content_sent(self, stream_id):
        _, outgoing = self._stream_data[stream_id]
        outgoing.content_sent()

    def stream_closed(self, stream_id, error_code):
        if stream_id not in self._stream_data:
            return

        for msg in self._stream_data[stream_id]:
            if msg is not None:
                msg.stream_closed(error_code)

        del self._stream_data[stream_id]

    def window_update_received(self, stream_id):
        waiter = self._window_update_waiters.get(stream_id, None)
        if waiter:
            del self._window_update_waiters[stream_id]
            waiter.set_result(None)

    def goaway_sent(self, error_code):
        self._goaway_error = ConnectionResetError('Connection lost ({})'.format(
            error_code.name)
        )
        waiter = self._goaway_waiter
        if waiter is not None:
            self._goaway_waiter = None
            waiter.set_result(error_code)

    def goaway_received(self, error_code):
        self._goaway_error = ConnectionResetError('Connection lost ({})'.format(
            error_code.name)
        )
        self.transport.close()


class ServerProtocol(BaseHTTP2):

    def __init__(self, on_request_callback, settings, loop):
        super().__init__(settings, loop)
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
        self.session.submit_settings(self._settings)

    def begin_headers(self, stream_id):
        req = Request(self, stream_id, direction=Direction.RECEIVING, loop=self.loop)
        self._stream_data[stream_id] = (req, None)

    def headers_received(self, stream_id):
        req, _ = self._stream_data[stream_id]
        req.headers_received()
        self._on_request(req)

    def content_received(self, stream_id):
        req, _ = self._stream_data[stream_id]
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
        self.session.submit_settings(self._settings)

    def begin_headers(self, stream_id):
        pass

    def headers_received(self, stream_id):
        resp, _ = self._stream_data[stream_id]
        resp.headers_received()

    def content_received(self, stream_id):
        resp, _ = self._stream_data[stream_id]
        resp.content.feed_eof()

    def stream_closed(self, stream_id, error_code):
        # If the stream was refused, reschedule the request and the response
        # into the pending queue
        if error_code == nghttp2.error_code.REFUSED_STREAM:
            if stream_id in self._stream_data:
                resp, req = self._stream_data.pop(stream_id)

                # Reset HTTP message
                req._headers_sent = False
                req._content_sent = False

                self._pending.appendleft((req, resp))

        super().stream_closed(stream_id, error_code)

    def submit_request(self, req, resp):
        if self._connection_lost:
            raise self._goaway_error
        
        self._pending.append((resp, req))

        # Submit pending requests and them to buffers
        self.flush()


class ServerSession(object):

    def __init__(self, host, port, settings=None, loop=None):
        self.host = host
        self.port = port
        self.loop = loop or asyncio.get_event_loop()
        self.server = None
        self._requests = collections.deque()
        self._waiter = None
        if settings is None:
            self._settings = [
                (nghttp2.settings_id.MAX_CONCURRENT_STREAMS, 10),
            ]
        else:
            self._settings = settings


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
            lambda: ServerProtocol(self._received_request, self._settings, self.loop),
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

    def __init__(self, host, port, settings=None, loop=None):
        self.host = host
        self.port = port
        self.loop = loop or asyncio.get_event_loop()
        self.protocol = None
        if settings is None:
            self._settings = [
                (nghttp2.settings_id.MAX_CONCURRENT_STREAMS, 10),
            ]
        else:
            self._settings = settings

    async def __aenter__(self):
        await self.start()
        return self

    async def __aexit__(self, *exc):
        await self.terminate()

    async def start(self):
        assert self.protocol is None, "ClientSession already started"
        _, self.protocol = await self.loop.create_connection(
            lambda: ClientProtocol(self._settings, self.loop),
            self.host, self.port)

    async def terminate(self, error_code=nghttp2.error_code.NO_ERROR):
        if self.protocol is None:
            return

        await self.protocol.terminate(error_code)
        self.protocol = None

    def request_allowed(self):
        if self.protocol is None:
            return False

        return self.protocol.session.request_allowed()

    def request(self, method=None, url=None, headers=None, data=None):
        if self.protocol is None:
            raise ConnectionError('Connection not established')

        # Generate leading pseudo header fields
        if url is not None and method is not None:
            _url = urlparse(url)
            _headers = [
                (':method', method),
                (':scheme', _url.scheme),
                (':authority', _url.netloc),
                (':path', _url.path),
            ]
            if headers:
                _headers.extend(headers)
        else:
            assert headers is not None, "Headers must be present if no URL or method is provided"
            _headers = headers

        req = Request(self.protocol, stream_id=None,
            headers=_headers, data=data,
            direction=Direction.SENDING, loop=self.loop
        )

        resp = Response(self.protocol, stream_id=None,
            direction=Direction.RECEIVING, loop=self.loop
        )

        self.protocol.submit_request(req, resp)

        return resp

    def get(self, url, headers=None):
        return self.request('GET', url, headers)

    def post(self, url, headers=None, data=None):
        return self.request('POST', url, headers, data)

