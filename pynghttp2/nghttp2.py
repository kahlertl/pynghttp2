"""Python wrapper for the nghttp2 API

The nghttp2 API is already object orientated but this module wraps the low-level
OOP in Python's own object model.
"""
import enum
from ctypes import *
from .typedefs import *
from .bindings import nghttp2


class Options(object):

    def __init__(self,
                 builtin_recv_extension_type=None,
                 max_deflate_dynamic_table_size=None,
                 max_reserved_remote_streams=None,
                 max_send_header_block_length=None,
                 no_auto_ping_ack=None,
                 no_auto_window_update=None,
                 no_closed_streams=None,
                 no_http_messaging=None,
                 no_recv_client_magic=None,
                 peer_max_concurrent_streams=None,
                 user_recv_extension_type=None):
        self._option = option_p()
        err = nghttp2.nghttp2_option_new(byref(self._option))

        if err == error.NOMEM:
            raise MemoryError()

        if builtin_recv_extension_type is not None:
            self.set_builtin_recv_extension_type(builtin_recv_extension_type)
        if max_deflate_dynamic_table_size is not None:
            self.set_max_deflate_dynamic_table_size(max_deflate_dynamic_table_size)
        if max_reserved_remote_streams is not None:
            self.set_max_reserved_remote_streams(max_reserved_remote_streams)
        if max_send_header_block_length is not None:
            self.set_max_send_header_block_length(max_send_header_block_length)
        if no_auto_ping_ack is not None:
            self.set_no_auto_ping_ack(no_auto_ping_ack)
        if no_auto_window_update is not None:
            self.set_no_auto_window_update(no_auto_window_update)
        if no_closed_streams is not None:
            self.set_no_closed_streams(no_closed_streams)
        if no_http_messaging is not None:
            self.set_no_http_messaging(no_http_messaging)
        if no_recv_client_magic is not None:
            self.set_no_recv_client_magic(no_recv_client_magic)
        if peer_max_concurrent_streams is not None:
            self.set_peer_max_concurrent_streams(peer_max_concurrent_streams)
        if user_recv_extension_type is not None:
            self.set_user_recv_extension_type(user_recv_extension_type)

    def set_builtin_recv_extension_type(self, type):
        """Sets extension frame type the application is willing to receive
        using builtin handler. The type is the extension frame type to
        receive, and must be strictly greater than 0x9. Otherwise, this
        function does nothing. The application can call this function multiple
        times to set more than one frame type to receive. The application does
        not have to call this function if it just sends extension frames.

        If same frame type is passed to both
        nghttp2_option_set_builtin_recv_extension_type() and
        nghttp2_option_set_user_recv_extension_type(), the latter takes
        precedence.
        """
        nghttp2.nghttp2_option_set_builtin_recv_extension_type(self._option, type)

    def set_max_deflate_dynamic_table_size(self, val):
        """This option sets the maximum dynamic table size for deflating
        header fields. The default value is 4KiB. In HTTP/2, receiver of
        deflated header block can specify maximum dynamic table size. The
        actual maximum size is the minimum of the size receiver specified and
        this option value.

        Args:
            val (int): Maximum dynamic table size
        """
        nghttp2.nghttp2_option_set_max_deflate_dynamic_table_size(self._option, val)

    def set_max_reserved_remote_streams(self, val):
        """RFC 7540 does not enforce any limit on the number of incoming
        reserved streams (in RFC 7540 terms, streams in reserved (remote)
        state). This only affects client side, since only server can push
        streams. Malicious server can push arbitrary number of streams, and
        make client's memory exhausted. This option can set the maximum number
        of such incoming streams to avoid possible memory exhaustion. If this
        option is set, and pushed streams are automatically closed on
        reception, without calling user provided callback, if they exceed the
        given limit. The default value is 200. If session is configured as
        server side, this option has no effect. Server can control the number
        of streams to push.

        Args:
            val (int): Max. number of reserved streams
        """
        nghttp2.nghttp2_option_set_max_reserved_remote_streams(self._option, val)

    def set_max_send_header_block_length(self, val):
        """This option sets the maximum length of header block (a set of
        header fields per one HEADERS frame) to send. The length of a given
        set of header fields is calculated using nghttp2_hd_deflate_bound().
        The default value is 64KiB. If application attempts to send header
        fields larger than this limit, the transmission of the frame fails
        with error code :attr:`error.FRAME_SIZE_ERROR`.

        Args:
            val (int): Max. length of header block to send
        """
        nghttp2.nghttp2_option_set_max_send_header_block_length(self._option, val)

    def set_no_auto_ping_ack(self, val):
        """This option prevents the library from sending PING frame with ACK
        flag set automatically when PING frame without ACK flag set is received.
        If this option is set to True, the library won't send PING frame with
        ACK flag set in the response for incoming PING frame. The application
        can send PING frame with ACK flag set using nghttp2_submit_ping() with
        :attr:`.typedefs.flag.ACK` as flags parameter.

        Args:
            val (bool): If True, the library won't answer PING frames
                automatically
        """
        nghttp2.nghttp2_option_set_no_auto_ping_ack(self._option, int(val))

    def set_no_auto_window_update(self, val):
        """This option prevents the library from sending WINDOW_UPDATE for a
        connection automatically. If this option is set to True, the
        library won't send WINDOW_UPDATE for DATA until application calls
        nghttp2_session_consume() to indicate the consumed amount of data.
        Don't use nghttp2_submit_window_update() for this purpose. By default,
        this option is set to zero.

        Args:
            val (bool): If True, disables automatic WINDOW_UPDATE frames
        """
        nghttp2.nghttp2_option_set_no_auto_window_update(self._option, int(val))

    def set_no_closed_streams(self, val):
        """This option prevents the library from retaining closed streams to
        maintain the priority tree. If this option is set to True,
        applications can discard closed stream completely to save memory.

        Args:
            val (bool): If True, library will not retain closed streams
        """
        nghttp2.nghttp2_option_set_no_closed_streams(self._option, int(val))

    def set_no_http_messaging(self, val):
        """By default, nghttp2 library enforces subset of HTTP Messaging rules
        described in HTTP/2 specification, section 8. See HTTP Messaging
        section for details. For those applications who use nghttp2 library as
        non-HTTP use, give True to val to disable this enforcement. Please
        note that disabling this feature does not change the fundamental
        client and server model of HTTP. That is, even if the validation is
        disabled, only client can send requests.

        Args:
            val (bool): If True, disables HTTP Messaging rules
        """
        nghttp2.nghttp2_option_set_no_http_messaging(self._option, bool(val))

    def set_no_recv_client_magic(self, val):
        """By default, nghttp2 library, if configured as server, requires
        first 24 bytes of client magic byte string (MAGIC). In most cases,
        this will simplify the implementation of server. But sometimes server
        may want to detect the application protocol based on first few bytes
        on clear text communication.

        If this option is used with True val, nghttp2 library does not
        handle MAGIC. It still checks following SETTINGS frame. This means
        that applications should deal with MAGIC by themselves.

        If this option is not used or used with zero value, if MAGIC does not
        match NGHTTP2_CLIENT_MAGIC, nghttp2_session_recv() and
        nghttp2_session_mem_recv() will return error
        :attr:`error.BAD_CLIENT_MAGIC`, which is fatal error.

        Args:
            val (bool): If True, library does not handle MAGIC
        """
        nghttp2.nghttp2_option_set_no_recv_client_magic(self._option, bool(val))

    def set_peer_max_concurrent_streams(self, val):
        """This option sets the attr:`settings.MAX_CONCURRENT_STREAMS` value
        of remote endpoint as if it is received in SETTINGS frame. Without
        specifying this option, before the local endpoint receives
        attr:`settings.MAX_CONCURRENT_STREAMS` in SETTINGS frame from remote
        endpoint, attr:`settings.MAX_CONCURRENT_STREAMS` is unlimited. This
        may cause problem if local endpoint submits lots of requests initially
        and sending them at once to the remote peer may lead to the rejection
        of some requests. Specifying this option to the sensible value, say
        100, may avoid this kind of issue. This value will be overwritten if
        the local endpoint receives attr:`settings.MAX_CONCURRENT_STREAMS`
        from the remote endpoint.

        Args:
            val (int): Max. number of concurrent streams per peer before local
                SETTINGS frame is send
        """
        nghttp2.nghttp2_option_set_peer_max_concurrent_streams(self._option, val)

    def set_user_recv_extension_type(self, val):
        """Sets extension frame type the application is willing to handle with
        user defined callbacks (see nghttp2_on_extension_chunk_recv_callback
        and nghttp2_unpack_extension_callback). The type is extension frame
        type, and must be strictly greater than 0x9. Otherwise, this function
        does nothing. The application can call this function multiple times to
        set more than one frame type to receive. The application does not have
        to call this function if it just sends extension frames.

        Args:
            val (int): type the application is willing to handle with user
                defined callbacks
        """
        nghttp2.nghttp2_option_set_user_recv_extension_type(self._option, val)

    def __del__(self):
        nghttp2.nghttp2_option_del(self._option)


def version():
    return nghttp2.nghttp2_version(c_int(0)).contents


def cast_py_object(ptr):
    try:
        return cast(ptr, py_object).value
    except ValueError:
        return None


def session_set_stream_user_data(session, stream_id, user_data):
    err = nghttp2.nghttp2_session_set_stream_user_data(session, stream_id, py_object(user_data))
    if err == error.INVALID_ARGUMENT:
        raise ValueError("Stream does not exist")


def session_get_stream_user_data(session, stream_id):
    ptr = nghttp2.nghttp2_session_get_stream_user_data(session, stream_id)
    return cast_py_object(ptr)


class session_type(enum.IntEnum):
    CLIENT = 0
    SERVER = 1


class Session(object):

    def __init__(self, type, callbacks, user_data=None, options=None):
        self._session = session_p()
        callbacks_p = session_callbacks_p()

        err = nghttp2.nghttp2_session_callbacks_new(byref(callbacks_p))
        if err == error.NOMEM:
            raise MemoryError()

        if 'send' in callbacks:
            nghttp2.nghttp2_session_callbacks_set_send_callback(callbacks_p, callbacks['send'])
        if 'send_data' in callbacks:
            nghttp2.nghttp2_session_callbacks_set_send_data_callback(callbacks_p, callbacks['send_data'])
        if 'on_frame_recv' in callbacks:
            nghttp2.nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks_p, callbacks['on_frame_recv'])
        if 'on_frame_send' in callbacks:
            nghttp2.nghttp2_session_callbacks_set_on_frame_send_callback(callbacks_p, callbacks['on_frame_send'])
        if 'on_data_chunk_recv' in callbacks:
            nghttp2.nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks_p, callbacks['on_data_chunk_recv'])
        if 'on_stream_close' in callbacks:
            nghttp2.nghttp2_session_callbacks_set_on_stream_close_callback(callbacks_p, callbacks['on_stream_close'])
        if 'on_header' in callbacks:
            nghttp2.nghttp2_session_callbacks_set_on_header_callback(callbacks_p, callbacks['on_header'])
        if 'on_begin_headers' in callbacks:
            nghttp2.nghttp2_session_callbacks_set_on_begin_headers_callback(callbacks_p, callbacks['on_begin_headers'])

        if type == session_type.CLIENT:
            if options is None:
                err = nghttp2.nghttp2_session_client_new(self._session, callbacks_p, py_object(user_data))
            else:
                err = nghttp2.nghttp2_session_client_new2(self._session, callbacks_p, py_object(user_data), options._option)
        elif type == session_type.SERVER:
            if options is None:
                err = nghttp2.nghttp2_session_server_new(self._session, callbacks_p, py_object(user_data))
            else:
                err = nghttp2.nghttp2_session_server_new2(self._session, callbacks_p, py_object(user_data), options._option)
        else:
            nghttp2.nghttp2_session_callbacks_del(callbacks_p)
            raise ValueError("Unknown session type")

        if err == error.NOMEM:
            nghttp2.nghttp2_session_callbacks_del(callbacks_p)
            raise MemoryError()

        nghttp2.nghttp2_session_callbacks_del(callbacks_p)

    def __del__(self):
        nghttp2.nghttp2_session_del(self._session)

    def submit_settings(self, settings):
        settings_array = settings_entry * len(settings)

        err = nghttp2.nghttp2_submit_settings(self._session, flag.NONE, settings_array(*settings), len(settings))
        if err == error.INVALID_ARGUMENT:
            raise ValueError("Invalid settings")
        if err == error.NOMEM:
            raise MemoryError()

    def set_stream_user_data(self, stream_id, user_data):
        session_set_stream_user_data(self._session, stream_id, user_data)

    def get_stream_user_data(self, stream_id):
        return session_get_stream_user_data(self._session, stream_id)

    def submit_request(self, headers, provider=None, stream_data=None, priority=None):
        header_array = (nv * len(headers))(
            *(nv(
                name=c_char_p(name.encode()),
                value=c_char_p(value.encode()),
                namelen=len(name),
                valuelen=len(value),
                flags=0
            ) for name, value in headers)
        )

        stream_id = nghttp2.nghttp2_submit_request(self._session, priority,
            header_array, len(header_array),
            provider, stream_data
        )

        if stream_id == error.NOMEM:
            raise MemoryError()
        if stream_id == error.STREAM_ID_NOT_AVAILABLE:
            raise ValueError("Stream ID not available")
        if stream_id == error.INVALID_ARGUMENT:
            raise ValueError("Invalid argument")
        if stream_id == error.PROTO:
            raise ValueError("Is server session")

        return stream_id

    def submit_headers(self, flags, stream_id, headers, priority=None):
        header_array = (nv * len(headers))(
            *(nv(
                name=c_char_p(name.encode()),
                value=c_char_p(value.encode()),
                namelen=len(name),
                valuelen=len(value),
                flags=0
            ) for name, value in headers)
        )

        err = nghttp2.nghttp2_submit_headers(self._session, flags, stream_id,
            priority, header_array, len(header_array), None)

        if err == error.NOMEM:
            raise MemoryError()
        if err == error.STREAM_ID_NOT_AVAILABLE:
            raise ValueError("Stream ID not available")
        if err == error.INVALID_ARGUMENT:
            raise ValueError("Invalid argument")
        if err == error.DATA_EXIST:
            raise ValueError("DATA or HEADERS already submitted")
        if err == error.PROTO:
            raise ValueError("Is server session")

    def submit_data(self, stream_id, provider, flags=flag.END_STREAM):
        err = nghttp2.nghttp2_submit_data(self._session, flags, stream_id, provider)

        if err == error.NOMEM:
            raise MemoryError()
        if err == error.DATA_EXIST:
            raise ValueError("DATA or HEADERS already submitted")
        if err == error.INVALID_ARGUMENT:
            raise ValueError("The stream_id is 0")
        if err == error.STREAM_CLOSED:
            raise ValueError("Stream closed or stream ID invalid")

    def submit_response(self, stream_id, headers, provider=None):
        header_array = (nv * len(headers))(
            *(nv(
                name=c_char_p(name.encode()),
                value=c_char_p(value.encode()),
                namelen=len(name),
                valuelen=len(value),
                flags=0
            ) for name, value in headers)
        )
        err = nghttp2.nghttp2_submit_response(self._session, stream_id,
            header_array, len(header_array), provider)

        if err == error.NOMEM:
            raise MemoryError()
        if err == error.INVALID_ARGUMENT:
            raise ValueError("Invalid argument")
        if err == error.DATA_EXIST:
            raise ValueError("DATA or HEADER already submitted")
        if err == error.PROTO:
            raise ValueError("Is client session")

    def resume_data(self, stream_id):
        err = nghttp2.nghttp2_session_resume_data(self._session, stream_id)

        if err == error.INVALID_ARGUMENT:
            raise ValueError("Stream does not exist or there is no deferred data")
        if err == error.NOMEM:
            raise MemoryError()

    def terminate(self, error_code=error_code.NO_ERROR):
        err = nghttp2.nghttp2_session_terminate_session(self._session, error_code)
        if err == error.NOMEM:
            raise MemoryError()

    def send(self):
        err = nghttp2.nghttp2_session_send(self._session)
        if err == error.NOMEM:
            raise MemoryError()
        if err == error.CALLBACK_FAILURE:
            raise RuntimeError("User callback failed")

    def mem_recv(self, data):
        read = nghttp2.nghttp2_session_mem_recv(self._session, c_char_p(data), len(data))
        if read == error.NOMEM:
            raise MemoryError()

        return read

    def mem_send(self):
        data_p = POINTER(c_uint8)()
        length = nghttp2.nghttp2_session_mem_send(self._session, byref(data_p))

        # TODO: No-Copy approach here?
        return string_at(data_p, size=length)

    def want_read(self):
        return bool(nghttp2.nghttp2_session_want_read(self._session))

    def want_write(self):
        return bool(nghttp2.nghttp2_session_want_write(self._session))

    def is_open(self):
        return self.want_read() or self.want_write()

    def consume(self, stream_id, size):
        err = nghttp2.nghttp2_session_consume(self._session, stream_id, size)

        if err == error.NOMEM:
            raise MemoryError()
        if err == error.INVALID_ARGUMENT:
            raise ValueError("Stream ID is 0")
        if err == error.INVALID_STATE:
            raise ValueError("Automatic WINDOW_UPDATE is enabled")

    def consume_connection(self, size):
        """Like :meth:`consume`, but this only tells library that size bytes
        were consumed only for connection level. Note that HTTP/2 maintains
        connection and stream level flow control windows independently.

        Args:
            size (int): Bytes consumed for the connection window
        Raises:
            ValueError: If automatic ``WINDOW_UPDATE`` is enabled
            MemoryError: Out of memory
        """
        err = nghttp2.nghttp2_session_consume_connection(self._session, size)

        if err == error.NOMEM:
            raise MemoryError()
        if err == error.INVALID_STATE:
            raise ValueError("Automatic WINDOW_UPDATE is enabled")

    def consume_stream(self, stream_id, size):
        """Like :meth:`consume`, but this only tells library that size bytes
        were consumed only for stream denoted by stream_id. Note that HTTP/2
        maintains connection and stream level flow control windows
        independently.

        Args:
            stream_id (int): Stream ID for which the window is maintained
            size (int): Bytes consumed for the stream window
        Raises:
            ValueError: If automatic ``WINDOW_UPDATE`` is enabled or the stream ID is 0
            MemoryError: Out of memory
        """
        err = nghttp2.nghttp2_session_consume_stream(self._session, stream_id, size)

        if err == error.NOMEM:
            raise MemoryError()
        if err == error.INVALID_ARGUMENT:
            raise ValueError("Stream ID is 0")
        if err == error.INVALID_STATE:
            raise ValueError("Automatic WINDOW_UPDATE is enabled")

    def get_local_window_size(self):
        return nghttp2.nghttp2_session_get_local_window_size(self._session)

    def get_stream_local_window_size(self, stream_id):
        return nghttp2.nghttp2_session_get_local_window_size(self._session, stream_id)
    
    def get_remote_window_size(self):
        return nghttp2.nghttp2_session_get_remote_window_size(self._session)

    def get_stream_remote_window_size(self, stream_id):
        return nghttp2.nghttp2_session_get_stream_remote_window_size(self._session, stream_id)

    def get_stream_local_close(self, stream_id):
        """Returns True if local peer half closed the given stream stream_id.
        Returns False if it did not.

        Args:
            stream_id (int): Stream identifier
        Returns:
            bool: True if the local peer has closed the stream
        Raises:
            ValueError: if no such stream exists.
        """
        closed = nghttp2.nghttp2_session_get_stream_local_close(self._session, stream_id)

        if closed == -1:
            raise ValueError("Local stream {} does not exist".format(stream_id))

        return bool(closed)

    def get_stream_remote_close(self, stream_id):
        """Returns True if remote peer half closed the given stream stream_id.
        Returns False if it did not.

        Args:
            stream_id (int): Stream identifier
        Returns:
            bool: True if the remote peer has closed the stream
        Raises:
            ValueError: if no such stream exists.
        """
        closed = nghttp2.nghttp2_session_get_stream_remote_close(self._session, stream_id)

        if closed == -1:
            raise ValueError("Remote stream {} does not exist".format(stream_id))

        return bool(closed)

    def stream_exists(self, stream_id):
        return bool(nghttp2.nghttp2_session_find_stream(self._session, stream_id))
