import asyncio
import collections
import io
from ctypes import addressof, c_uint8
from . import nghttp2


class StreamReader(object):

    def __init__(self, loop=None):
        self._loop = loop or asyncio.get_event_loop()
        self._eof = False
        self._buffer = collections.deque()
        self._size = 0
        self._offset = 0
        self._waiter = None
        self._eof_waiter = None
        self._exception = None

        self._reading_deferred = False
        self._protocol = None
        self._stream_id = None

    def set_exception(self, exc):
        if self._eof:
            return

        self._exception = exc

        waiter = self._waiter
        if waiter is not None:
            self._waiter = None
            waiter.set_exception(exc)

        waiter = self._eof_waiter
        if waiter is not None:
            self._eof_waiter = None
            waiter.set_exception(exc)

    def is_eof(self):
        """Return True if :meth:`feed_eof` was called."""
        return self._eof

    def at_eof(self):
        """Return True if the buffer is empty and :meth:`feed_eof` was called."""
        return self._eof and not self._buffer

    def empty(self):
        return self._size == 0

    def is_deferred(self):
        return self._reading_deferred

    def reading_deferred(self):
        """Deferr reading until feed_data is called"""
        assert not self._reading_deferred, "Reading already deferred"
        self._reading_deferred = True

    def reading_resumed(self):
        assert self._reading_deferred, "Reading not deferred"
        self._reading_deferred = False

        if self._protocol is not None:
            self._protocol.session.resume_data(self._stream_id)


    async def read(self, n=-1):
        if self._exception is not None:
            raise self._exception

        if n == 0:
            return b''

        # Read until EOF
        if n < 0:
            blocks = []
            while True:
                block = await self.readany()
                if not block:
                    break
                blocks.append(block)
            return b''.join(blocks)

        if not self._buffer and not self._eof:
            waiter = self._loop.create_future()
            self._waiter = waiter

            try:
                await self._waiter
            except (asyncio.CancelledError, asyncio.TimeoutError):
                self._waiter = None
                raise

        data = self.read_nowait(n)
        self._consume_window(data)
        return data

    async def readany(self):
        if self._exception is not None:
            raise self._exception

        if not self._buffer and not self._eof:
            await self._wait()

        data = self.read_nowait(-1)
        self._consume_window(data)
        return data

    def read_nowait(self, n):
        size = n
        prev = self._size

        chunks = []

        while self._buffer:
            chunk = self._read_nowait_chunk(n)
            chunks.append(chunk)
            if n != -1:
                n -= len(chunk)
                if n == 0:
                    break

        if chunks:
            data = b''.join(chunks)
            return data

        return b''

    async def _wait(self):
        assert self._waiter is None

        waiter = self._loop.create_future()
        self._waiter = waiter

        try:
            await self._waiter
        except (asyncio.CancelledError, asyncio.TimeoutError):
            self._waiter = None
            raise

    async def wait_eof(self):
        if self._eof:
            return

        assert self._eof_waiter is None

        waiter = self._loop.create_future()
        self._eof_waiter = waiter
        try:
            await self._eof_waiter
        finally:
            self._eof_waiter = None

    def set_protocol(self, protocol, stream_id):
        assert self._protocol is None, "Protocol already set"
        self._protocol = protocol
        self._stream_id = stream_id

    async def drain(self):
        assert self._protocol, "No protocol set"

        if self._exception is not None:
            raise self._exception

        # If reading is deferred the nghttp2 session will call the read callack
        # for the stream. Hence, self._protocol.flush() will have no effect and
        # read no data from the reader.
        if self.is_deferred():
            return

        # Wait for WINDOW_UPDATE frame if the session cannot write anymore DATA
        # to the stream but there is still data remaining
        if not self.empty() and not self._protocol.can_write_stream(self._stream_id):
            await self._protocol.wait_for_window_update(self._stream_id)

        self._protocol.flush()
        await self._protocol.drain()

    def feed_data(self, data):
        assert not self._eof, 'feed_data after feed_eof'

        if not data:
            return

        self._buffer.append(data)
        self._size += len(data)

        if self.is_deferred():
            self.reading_resumed()

        # TODO: Use low and high water marks

        waiter = self._waiter
        if waiter is not None:
            self._waiter = None
            if not waiter.cancelled():
                waiter.set_result(None)

    def feed_eof(self):
        self._eof = True

        if self.is_deferred():
            self.reading_resumed()

        waiter = self._waiter
        if waiter is not None:
            self._waiter = None
            if not waiter.done():
                waiter.set_result(None)

        waiter = self._eof_waiter
        if waiter is not None:
            self._eof_waiter = None
            if not waiter.done():
                waiter.set_result(None)

    def _read_nowait_chunk(self, n):
        first_buffer = self._buffer[0]
        offset = self._offset

        if n != -1 and len(first_buffer) - offset > n:
            data = first_buffer[offset:offset + n]
            self._offset += n

        elif offset:
            self._buffer.popleft()
            data = first_buffer[offset:]
            self._offset = 0

        else:
            data = self._buffer.popleft()

        self._size -= len(data)
        return data

    def _consume_window(self, data):
        if self._protocol is None or self._eof:
            return

        if not data:
            return

        # Notify nghttp2 about consumption and eventually enqueue a
        # WINDOW_UPDATE frame
        self._protocol.session.consume_stream(self._stream_id, len(data))

        # Send outstanding WINDOW_UPDATE frames
        self._protocol.flush()


def make_stream_reader(data, headers):
    if data is None:
        # Empty response. Create a stream reader and immediately feed EOF
        content = StreamReader()
        content.feed_eof()
        return content

    if isinstance(data, str):
        data = data.encode()

    if isinstance(data, bytes):
        # Fixed bytes content. Create stream reader, feed all bytes to it
        # and terminate further feeding with EOF.
        #
        # The length of the stream is known, hence a Content-Length header
        # is added.
        content = StreamReader()
        content.feed_data(data)
        content.feed_eof()
        headers.append(('content-length', str(len(data))))
        return content

    return data


#: Minimal size of a DATA block. If a stream reader 
DATA_MIN_SIZE = 128

@nghttp2.data_source_read_callback
def read_data_source(session, stream_id, buf, length, data_flags, source, user_data):
    reader = source[0].ptr

    # Check if enough data is in the buffer. If not and EOF is set yet, deferr
    # the reading until the next feed_data or feed_eof call.
    if reader._size < min(length, DATA_MIN_SIZE) and not reader.is_eof():
        reader.reading_deferred()
        return nghttp2.error.DEFERRED

    chunk = reader.read_nowait(length)

    if reader.at_eof():
        data_flags[0] = nghttp2.data_flag.EOF

    data = (c_uint8 * length).from_address(addressof(buf.contents))
    return io.BytesIO(chunk).readinto(data)
