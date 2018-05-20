from ctypes import *
import struct
import enum


nghttp2 = CDLL('libnghttp2.so')


class error(enum.IntEnum):
    """Error codes used in the nghttp2 library. The code range is [-999, -500],
    inclusive."""

    #: Invalid argument passed.
    INVALID_ARGUMENT = -501

    #: Out of buffer space.
    BUFFER_ERROR = -502

    #: The specified protocol version is not supported.
    UNSUPPORTED_VERSION = -503

    #: Used as a return value from send_callback, recv_callback
    #: and send_data_callback to indicate that the operation would block.
    WOULDBLOCK = -504

    #: General protocol error
    PROTO = -505

    #: The frame is invalid.
    INVALID_FRAME = -506

    #: The peer performed a shutdown on the connection.
    EOF = -507

    #: Used as a return value from data_source_read_callback() to
    #: indicate that data transfer is postponed. See
    #: data_source_read_callback() for details.
    DEFERRED = -508

    #: Stream ID has reached the maximum value. Therefore no stream ID is
    #: available.
    STREAM_ID_NOT_AVAILABLE = -509

    #: The stream is already closed; or the stream ID is invalid.
    STREAM_CLOSED = -510

    #: RST_STREAM has been added to the outbound queue. The stream is in closing
    #: state.
    STREAM_CLOSING = -511

    #: The transmission is not allowed for this stream (e.g., a frame with
    #: END_STREAM flag set has already sent).
    STREAM_SHUT_WR = -512

    #: The stream ID is invalid.
    INVALID_STREAM_ID = -513

    #: The state of the stream is not valid (e.g., DATA cannot be sent to the
    #: stream if response HEADERS has not been sent).
    INVALID_STREAM_STATE = -514

    #: Another DATA frame has already been deferred.
    DEFERRED_DATA_EXIST = -515

    #: Starting new stream is not allowed (e.g., GOAWAY has been sent and/or
    #: received).
    START_STREAM_NOT_ALLOWED = -516

    #: GOAWAY has already been sent.
    GOAWAY_ALREADY_SENT = -517

    #: The received frame contains the invalid header block (e.g., There are
    #: duplicate header names; or the header names are not encoded in US-ASCII
    #: character set and not lower cased; or the header name is zero-length
    #: string; or the header value contains multiple in-sequence NUL bytes).
    INVALID_HEADER_BLOCK = -518

    #: Indicates that the context is not suitable to perform the requested
    #: operation.
    INVALID_STATE = -519

    #: The user callback function failed due to the temporal error.
    TEMPORAL_CALLBACK_FAILURE = -521

    #: The length of the frame is invalid, either too large or too small.
    FRAME_SIZE_ERROR = -522

    #: Header block inflate/deflate error.
    HEADER_COMP = -523

    #: Flow control error
    FLOW_CONTROL = -524

    #: Insufficient buffer size given to function.
    INSUFF_BUFSIZE = -525

    #: Callback was paused by the application
    PAUSE = -526

    #: There are too many in-flight SETTING frame and no more transmission of
    #: SETTINGS is allowed.
    TOO_MANY_INFLIGHT_SETTINGS = -527

    #: The server push is disabled.
    PUSH_DISABLED = -528

    #: DATA or HEADERS frame for a given stream has been already submitted and
    #: has not been fully processed yet. Application should wait for the
    #: transmission of the previously submitted frame before submitting another.
    DATA_EXIST = -529

    #: The current session is closing due to a connection error or
    #: session_terminate_session() is called.
    SESSION_CLOSING = -530

    #: Invalid HTTP header field was received and stream is going to be closed.
    HTTP_HEADER = -531

    #: Violation in HTTP messaging rule.
    HTTP_MESSAGING = -532

    #: Stream was refused.
    REFUSED_STREAM = -533

    #: Unexpected internal error, but recovered.
    INTERNAL = -534

    #: Indicates that a processing was canceled.
    CANCEL = -535

    #: When a local endpoint expects to receive SETTINGS frame, it receives an
    #: other type of frame.
    SETTINGS_EXPECTED = -536

    #: The errors < FATAL mean that the library is under unexpected
    #: condition and processing was terminated (e.g., out of memory). If
    #: application receives this error code, it must stop using that
    #: session object and only allowed operation for that object is
    #: deallocate it using session_del().
    FATAL = -900

    #: Out of memory. This is a fatal error.
    NOMEM = -901

    #: The user callback function failed. This is a fatal error.
    CALLBACK_FAILURE = -902

    #: Invalid client magic (see NGHTTP2_CLIENT_MAGIC) was received and further
    #: processing is not possible.
    BAD_CLIENT_MAGIC = -903

    #: Possible flooding by peer was detected in this HTTP/2 session. Flooding is
    #: measured by how many PING and SETTINGS frames with ACK flag set are queued
    #: for transmission. These frames are response for the peer initiated frames,
    #: and peer can cause memory exhaustion on server side to send these frames
    #: forever and does not read network.
    FLOODED = -904


class error_code(enum.IntEnum):
    """The status codes for the RST_STREAM and GOAWAY frames."""

    #: No errors.
    NO_ERROR = 0x00

    #: PROTOCOL_ERROR
    PROTOCOL_ERROR = 0x01

    #: INTERNAL_ERROR
    INTERNAL_ERROR = 0x02

    #: FLOW_CONTROL_ERROR
    FLOW_CONTROL_ERROR = 0x03

    #: SETTINGS_TIMEOUT
    SETTINGS_TIMEOUT = 0x04

    #: STREAM_CLOSED
    STREAM_CLOSED = 0x05

    #: FRAME_SIZE_ERROR
    FRAME_SIZE_ERROR = 0x06

    #: REFUSED_STREAM
    REFUSED_STREAM = 0x07

    #: CANCEL
    CANCEL = 0x08

    #: COMPRESSION_ERROR
    COMPRESSION_ERROR = 0x09

    #: CONNECT_ERROR
    CONNECT_ERROR = 0x0a

    #: ENHANCE_YOUR_CALM
    ENHANCE_YOUR_CALM = 0x0b

    #: INADEQUATE_SECURITY
    INADEQUATE_SECURITY = 0x0c

    #: HTTP_1_1_REQUIRED
    HTTP_1_1_REQUIRED = 0x0d


class data_flag(enum.IntFlag):
    """The flags used to set in data_flags output parameter in
    data_source_read_callback.
    """

    #: No flag set.
    NONE = 0

    #: Indicates EOF was sensed.
    EOF = 0x01

    #: Indicates that END_STREAM flag must not be set even if
    #: EOF is set. Usually this flag is used to send trailer
    #: fields with submit_request() or submit_response().
    NO_END_STREAM = 0x02

    #: Indicates that application will send complete DATA frame in
    #: send_data_callback.
    NO_COPY = 0x04


class nv_flag(enum.IntFlag):
    """The flags for header field name/value pair."""

    #: No flag set.
    NONE = 0

    #: Indicates that this name/value pair must not be indexed (“Literal Header
    #: Field never Indexed” representation must be used in HPACK encoding). Other
    #: implementation calls this bit as “sensitive”.
    NO_INDEX = 0x01

    #: This flag is set solely by application. If this flag is set, the library
    #: does not make a copy of header field name. This could improve performance.
    NO_COPY_NAME = 0x02

    #: This flag is set solely by application. If this flag is set, the library
    #: does not make a copy of header field value. This could improve
    #: performance.
    NO_COPY_VALUE = 0x04


class frame_type(enum.IntEnum):
    """The frame types in HTTP/2 specification."""

    #: The DATA frame.
    DATA = 0

    #: The HEADERS frame.
    HEADERS = 0x01

    #: The PRIORITY frame.
    PRIORITY = 0x02

    #: The RST_STREAM frame.
    RST_STREAM = 0x03

    #: The SETTINGS frame.
    SETTINGS = 0x04

    #: The PUSH_PROMISE frame.
    PUSH_PROMISE = 0x05

    #: The PING frame.
    PING = 0x06

    #: The GOAWAY frame.
    GOAWAY = 0x07

    #: The WINDOW_UPDATE frame.
    WINDOW_UPDATE = 0x08

    #: The CONTINUATION frame. This frame type won’t be passed to any callbacks
    #: because the library processes this frame type and its preceding
    #: HEADERS/PUSH_PROMISE as a single frame.
    CONTINUATION = 0x09

    #: The ALTSVC frame, which is defined in RFC 7383.
    ALTSVC = 0x0a


class flag(enum.IntEnum):
    """The flags for HTTP/2 frames. This enum defines all flags for all frames."""

    #: No flag set.
    NONE = 0

    #: The END_STREAM flag.
    END_STREAM = 0x01

    #: The END_HEADERS flag.
    END_HEADERS = 0x04

    #: The ACK flag.
    ACK = 0x01

    #: The PADDED flag.
    PADDED = 0x08

    #: The PRIORITY flag.
    PRIORITY = 0x20


class settings_id(enum.IntEnum):
    """The SETTINGS ID"""

    #: SETTINGS_HEADER_TABLE_SIZE
    HEADER_TABLE_SIZE = 0x01

    #: SETTINGS_ENABLE_PUSH
    ENABLE_PUSH = 0x02

    #: SETTINGS_MAX_CONCURRENT_STREAMS
    MAX_CONCURRENT_STREAMS = 0x03

    #: SETTINGS_INITIAL_WINDOW_SIZE
    INITIAL_WINDOW_SIZE = 0x04

    #: SETTINGS_MAX_FRAME_SIZE
    MAX_FRAME_SIZE = 0x05

    #: SETTINGS_MAX_HEADER_LIST_SIZE
    MAX_HEADER_LIST_SIZE = 0x06


class headers_category(enum.IntEnum):
    """The category of HEADERS, which indicates the role of the frame. In HTTP/2
    spec, request, response, push response and other arbitrary headers (e.g.,
    trailer fields) are all called just HEADERS. To give the application the
    role of incoming HEADERS frame, we define several categories.
    """

    #: The HEADERS frame is opening new stream, which is analogous to SYN_STREAM
    #: in SPDY.
    REQUEST = 0

    #: The HEADERS frame is the first response headers, which is analogous to
    #: SYN_REPLY in SPDY.
    RESPONSE = 1

    #: The HEADERS frame is the first headers sent against reserved stream.
    PUSH_RESPONSE = 2

    #: The HEADERS frame which does not apply for the above categories, which is
    #: analogous to HEADERS in SPDY. If non-final response (e.g., status 1xx) is
    #: used, final response HEADERS frame will be categorized here.
    HEADERS = 3


class hd_inflate_flag(enum.IntFlag):
    """The flags for header inflation."""

    #: No flag set.
    NONE = 0

    #: Indicates all headers were inflated.
    FINAL = 0x01

    #: Indicates a header was emitted.
    EMIT = 0x02


class stream_proto_state(enum.IntEnum):
    """State of stream as described in RFC 7540."""

    #: idle state.
    IDLE = 1

    #: open state.
    OPEN = 2

    #: reserved (local) state.
    RESERVED_LOCAL = 3

    #: reserved (remote) state.
    RESERVED_REMOTE = 4

    #: half closed (local) state.
    HALF_CLOSED_LOCAL = 5

    #: half closed (remote) state.
    HALF_CLOSED_REMOTE = 6

    #: closed state.
    CLOSED = 7


# Pointers to opaque structs
session_p = c_void_p
stream_p = c_void_p
option_p = c_void_p
session_callbacks_p = c_void_p


class info(Structure):
    _fields_ = [
        ('age', c_int),
        ('version_num', c_int),
        ('version_str', c_char_p),
        ('proto_str', c_char_p),
    ]

    @property
    def version(self):
        return self.version_str.decode()

    @property
    def version_info(self):
        major, minor, patch = self.version_str.split(b'.')
        return (int(major), int(minor), int(patch))

    @property
    def proto(self):
        return self.proto_str.decode()

    def __repr__(self):
        return "<info age={} version_num={} version={} proto={}>".format(
            self.age,
            self.version_num,
            self.version_str.decode(),
            self.proto_str.decode(),
        )


class frame_hd(Structure):
    """The frame header

    Attrs:
        length (size_t):
            The length field of this frame, excluding frame header.
        stream_id (int32_t):
            The stream identifier (aka, stream ID)
        type (uint8_t):
            The type of this frame. See frame_type().
        flags (uint8_t):
            The flags.
        reserved (uint8_t):
            Reserved bit in frame header. Currently, this is always set to 0 and
            application should not expect something useful in here.
    """
    _fields_ = [
        ('length', c_size_t),
        ('stream_id', c_uint32),
        ('type', c_uint8),
        ('flags', c_uint8),
        ('reserved', c_uint8),
    ]


class data_source(Union):
    """This union represents the some kind of data source passed to
    data_source_read_callback.

    Attrs:
        fd (int):
            The integer field, suitable for a file descriptor.
        ptr (*void):
            The pointer to an arbitrary object.
    """
    _fields_ = [
        ('fd', c_int),
        ('ptr', py_object),
    ]


data_source_read_callback = CFUNCTYPE(c_ssize_t, session_p, c_int32, POINTER(c_uint8), c_size_t, POINTER(c_uint32), POINTER(data_source), py_object)

class data_provider(Structure):
    """This struct represents the data source and the way to read a chunk of
    data from it.

    Attrs:
        source (data_source):
            The data source.
        read_callback (data_source_read_callback):
            The callback function to read a chunk of data from the source.
    """
    _fields_ = [
        ('source', data_source),
        ('read_callback', data_source_read_callback)
    ]


class data(Structure):
    """The DATA frame. The received data is delivered via
    on_data_chunk_recv_callback.

    Attrs:
        padlen (size_t):
            The length of the padding in this frame. This includes PAD_HIGH and
            PAD_LOW.
    """
    _fields_ = [
        ('padlen', c_size_t),
    ]


class priority_spec(Structure):
    """The structure to specify stream dependency

    Attrs:
        stream_id (int32_t):
            The stream ID of the stream to depend on. Specifying 0 makes stream
            not depend any other stream.
        weight (int32_t):
            The weight of this dependency.
        exclusive (uint8_t):
            nonzero means exclusive dependency
    """
    _fields_ = [
        ('stream_id', c_int32),
        ('weight', c_int32),
        ('exclusive', c_uint8),
    ]


class nv(Structure):
    """The name/value pair, which mainly used to represent header fields.

    name (uint8_t*):
        The name byte string. If this struct is presented from library (e.g.,
        on_frame_recv_callback), name is guaranteed to be
        NULL-terminated. For some callbacks (before_frame_send_callback,
        on_frame_send_callback, and on_frame_not_send_callback),
        it may not be NULL-terminated if header field is passed from application
        with the flag NO_COPY_NAME). When application is
        constructing this struct, name is not required to be NULL-terminated.
    value (uint8_t*):
        The value byte string. If this struct is presented from library (e.g.,
        on_frame_recv_callback), value is guaranteed to be
        NULL-terminated. For some callbacks (before_frame_send_callback,
        on_frame_send_callback, and on_frame_not_send_callback),
        it may not be NULL-terminated if header field is passed from application
        with the flag NO_COPY_VALUE). When application is
        constructing this struct, value is not required to be NULL-terminated.
    namelen (size_t):
        The length of the name, excluding terminating NULL.
    valuelen (size_t):
        The length of the value, excluding terminating NULL.
    flags (uint8_t):
        Bitwise OR of one or more of :class:`nv_flag`.
    """
    _fields_ = [
        ('name', c_char_p),
        ('value', c_char_p),
        ('namelen', c_size_t),
        ('valuelen', c_size_t),
        ('flags', c_uint8),
    ]


class headers(Structure):
    """The HEADERS frame. It has the following members:

    Attrs:
        hd (frame_hd):
            The frame header.
        padlen (size_t):
            The length of the padding in this frame. This includes PAD_HIGH and
            PAD_LOW.
        pri_spec (priority_spec):
            The priority specification
        nva (*nv):
            The name/value pairs.
        nvlen (size_t):
            The number of name/value pairs in nva.
        cat (headers_category):
            The category of this HEADERS frame.
    """
    _fields_ = [
        ('hd', frame_hd),
        ('padlen', c_size_t),
        ('pri_spec', priority_spec),
        ('nva', POINTER(nv)),
        ('nvlen', c_size_t),
        ('cat', c_int),
    ]


class priority(Structure):
    """The PRIORITY frame. It has the following members:

    Attrs:
        hd (frame_hd):
            The frame header.
        pri_spec (priority_spec):
            The priority specification.
    """
    _fields_ = [
        ('hd', frame_hd),
        ('pri_spec', priority_spec),
    ]



class rst_stream(Structure):
    """The RST_STREAM frame. It has the following members:

    Attrs:
        hd (frame_hd):
            The frame header.
        error_code (uint32_t):
            The error code. See error_code.
    """
    _fields_ = [
        ('hd', frame_hd),
        ('error_code', c_uint32)
    ]


class settings_entry(Structure):
    """The SETTINGS ID/Value pair. It has the following members:

    Attrs:
        settings_id (int32_t):
            The SETTINGS ID. See settings_id.
        value (uint32_t):
            The value of this entry.
    """
    _fields_ = [
        ('settings_id', c_int32),
        ('value', c_uint32),
    ]


class settings(Structure):
    """The SETTINGS frame. It has the following members:

    Attrs:
        hd (frame_hd):
            The frame header.
        niv (size_t):
            The number of SETTINGS ID/Value pairs in iv.
        iv (*settings_entry):
            The pointer to the array of SETTINGS ID/Value pair.
    """
    _fields_ = [
        ('hd', frame_hd),
        ('niv', c_size_t),
        ('iv', POINTER(settings_entry)),
    ]


class push_promise(Structure):
    """The PUSH_PROMISE frame. It has the following members:

    Attrs:
        hd (frame_hd):
            The frame header.
        padlen (size_t):
            The length of the padding in this frame. This includes PAD_HIGH and
            PAD_LOW.
        nva (*nv):
            The name/value pairs.
        nvlen (size_t):
            The number of name/value pairs in nva.
        promised_stream_id (int32_t):
            The promised stream ID
        reserved (uint8_t):
            Reserved bit. Currently this is always set to 0 and application
            should not expect something useful in here.
    """
    _fields_ = [
        ('hd', frame_hd),
        ('padlen', c_size_t),
        ('nva', POINTER(nv)),
        ('nvlen', c_size_t),
        ('promised_stream_id', c_int32),
        ('reserved', c_uint8),
    ]


class ping(Structure):
    """The PING frame. It has the following members:

    Attrs:
        hd (frame_hd):
            The frame header.
        opaque_data (uint8_t[8]):
            The opaque data
    """
    _fields_ = [
        ('hd', frame_hd),
        ('opaque_data', c_uint8 * 8),
    ]


class goaway(Structure):
    """The GOAWAY frame. It has the following members:

    Attrs:
        hd (frame_hd):
            The frame header.
        last_stream_id (int32_t):
            The last stream stream ID.
        error_code (uint32_t):
            The error code. See error_code.
        *opaque_data (uint8_t):
            The additional debug data
        opaque_data_len (size_t):
            The length of opaque_data member.
        reserved (uint8_t):
            Reserved bit. Currently this is always set to 0 and application
            should not expect something useful in here.
    """
    _fields_ = [
        ('hd', frame_hd),
        ('last_stream_id', c_int32),
        ('error_code', c_uint32),
        ('opaque_data', c_uint8),
        ('opaque_data_len', c_size_t),
        ('reserved', c_uint8),
    ]


class window_update(Structure):
    """The WINDOW_UPDATE frame. It has the following members:

    Attrs:
        hd (frame_hd):
            The frame header.
        window_size_increment (int32_t):
            The window size increment.
        reserved (uint8_t):
            Reserved bit. Currently this is always set to 0 and application
            should not expect something useful in here.
    """
    _fields_ = [
        ('hd', frame_hd),
        ('window_size_increment', c_int32),
        ('reserved', c_uint8),
    ]


class extension(Structure):
    """The extension frame. It has following members:

    Attrs:
        hd (frame_hd):
            The frame header.
        payload (*void):
            The pointer to extension payload. The exact pointer type is
            determined by hd.type.

            Currently, no extension is supported. This is a place holder for the
            future extensions.
    """
    _fields_ = [
        ('hd', frame_hd),
        ('payload', c_void_p),
    ]


class frame(Union):
    """This union includes all frames to pass them to various function calls as
    frame type. The CONTINUATION frame is omitted from here because the
    library deals with it internally.

    Attrs:
        hd (frame_hd):
            The frame header, which is convenient to inspect frame header.
        data (data):
            The DATA frame.
        headers (headers):
            The HEADERS frame.
        priority (priority):
            The PRIORITY frame.
        rst_stream (rst_stream):
            The RST_STREAM frame.
        settings (settings):
            The SETTINGS frame.
        push_promise (push_promise):
            The PUSH_PROMISE frame.
        ping (ping):
            The PING frame.
        goaway (goaway):
            The GOAWAY frame.
        window_update (window_update):
            The WINDOW_UPDATE frame.
        ext (extension):
            The extension frame.
    """
    _fields_ = [
        ('hd', frame_hd),
        ('data', data),
        ('headers', headers),
        ('priority', priority),
        ('rst_stream', rst_stream),
        ('settings', settings),
        ('push_promise', push_promise),
        ('ping', ping),
        ('goaway', goaway),
        ('window_update', window_update),
        ('ext', extension),
    ]


nghttp2.nghttp2_option_new.argtypes = [POINTER(option_p)]
nghttp2.nghttp2_option_new.restype = c_int

nghttp2.nghttp2_option_del.argtypes = [option_p]
nghttp2.nghttp2_option_set_builtin_recv_extension_type.argtypes = [option_p, c_uint8]
nghttp2.nghttp2_option_set_max_deflate_dynamic_table_size.argtypes = [option_p, c_size_t]
nghttp2.nghttp2_option_set_max_reserved_remote_streams.argtypes = [option_p, c_uint32]
nghttp2.nghttp2_option_set_max_send_header_block_length.argtypes = [option_p, c_size_t]
nghttp2.nghttp2_option_set_no_auto_ping_ack.argtypes = [option_p, c_int]
nghttp2.nghttp2_option_set_no_auto_window_update.argtypes = [option_p, c_int]
nghttp2.nghttp2_option_set_no_closed_streams.argtypes = [option_p, c_int]
nghttp2.nghttp2_option_set_no_http_messaging.argtypes = [option_p, c_int]
nghttp2.nghttp2_option_set_no_recv_client_magic.argtypes = [option_p, c_int]
nghttp2.nghttp2_option_set_peer_max_concurrent_streams.argtypes = [option_p, c_uint32]
nghttp2.nghttp2_option_set_user_recv_extension_type.argtypes = [option_p, c_uint8]


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
        flag set automatically when PING frame without ACK flag set is
        received. If this option is set to True, the library won't send
        PING frame with ACK flag set in the response for incoming PING frame.
        The application can send PING frame with ACK flag set using
        nghttp2_submit_ping() with :attr:`flag.ACK` as flags parameter.

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


# Session callback types
send_callback = CFUNCTYPE(c_ssize_t, session_p, POINTER(c_uint8), c_size_t, c_int, py_object)
send_data_callback = CFUNCTYPE(c_int, session_p, POINTER(frame), POINTER(c_uint8), c_size_t, POINTER(data_source), py_object)
on_frame_recv_callback = CFUNCTYPE(c_int, session_p, POINTER(frame), py_object)
on_frame_send_callback = CFUNCTYPE(c_int, session_p, POINTER(frame), py_object)
on_data_chunk_recv_callback = CFUNCTYPE(c_int, session_p, c_uint8, c_int32, POINTER(c_uint8), c_size_t, py_object)
on_stream_close_callback = CFUNCTYPE(c_int, session_p, c_int32, c_uint32, py_object)
on_header_callback = CFUNCTYPE(c_int, session_p, POINTER(frame), POINTER(c_uint8), c_size_t, POINTER(c_uint8), c_size_t, c_uint8, py_object)
on_begin_headers_callback = CFUNCTYPE(c_int, session_p, POINTER(frame), py_object)


nghttp2.nghttp2_version.argtypes = [c_int]
nghttp2.nghttp2_version.restype = POINTER(info)

def version():
    return nghttp2.nghttp2_version(c_int(0)).contents



nghttp2.nghttp2_session_callbacks_del.argtypes = [session_callbacks_p]

nghttp2.nghttp2_session_callbacks_new.argtypes = [POINTER(session_callbacks_p)]
nghttp2.nghttp2_session_callbacks_new.restype = c_int

# nghttp2.nghttp2_session_callbacks_set_before_frame_send_callback
# nghttp2.nghttp2_session_callbacks_set_data_source_read_length_callback
# nghttp2.nghttp2_session_callbacks_set_error_callback
# nghttp2.nghttp2_session_callbacks_set_error_callback2
# nghttp2.nghttp2_session_callbacks_set_on_begin_frame_callback
nghttp2.nghttp2_session_callbacks_set_on_begin_headers_callback.argtypes = [session_callbacks_p, on_begin_headers_callback]
nghttp2.nghttp2_session_callbacks_set_on_data_chunk_recv_callback.argtypes = [session_callbacks_p, on_data_chunk_recv_callback]
# nghttp2.nghttp2_session_callbacks_set_on_extension_chunk_recv_callback
# nghttp2.nghttp2_session_callbacks_set_on_frame_not_send_callback
nghttp2.nghttp2_session_callbacks_set_on_frame_recv_callback.argtypes = [session_callbacks_p, on_frame_recv_callback]
nghttp2.nghttp2_session_callbacks_set_on_frame_send_callback.argtypes = [session_callbacks_p, on_frame_send_callback]
nghttp2.nghttp2_session_callbacks_set_on_header_callback.argtypes = [session_callbacks_p, on_header_callback]
# nghttp2.nghttp2_session_callbacks_set_on_header_callback2
# nghttp2.nghttp2_session_callbacks_set_on_invalid_frame_recv_callback
# nghttp2.nghttp2_session_callbacks_set_on_invalid_header_callback
# nghttp2.nghttp2_session_callbacks_set_on_invalid_header_callback2
nghttp2.nghttp2_session_callbacks_set_on_stream_close_callback.argtypes = [session_callbacks_p, on_stream_close_callback]
# nghttp2.nghttp2_session_callbacks_set_pack_extension_callback
# nghttp2.nghttp2_session_callbacks_set_recv_callback
# nghttp2.nghttp2_session_callbacks_set_select_padding_callback
nghttp2.nghttp2_session_callbacks_set_send_callback.argtypes = [session_callbacks_p, send_callback]
nghttp2.nghttp2_session_callbacks_set_send_data_callback.argtypes = [session_callbacks_p, send_data_callback]
# nghttp2.nghttp2_session_callbacks_set_unpack_extension_callback


nghttp2.nghttp2_session_client_new.argtypes = [POINTER(session_p), session_callbacks_p, py_object]
nghttp2.nghttp2_session_client_new.restype = c_int

nghttp2.nghttp2_session_client_new2.argtypes = [POINTER(session_p), session_callbacks_p, py_object, option_p]
nghttp2.nghttp2_session_client_new2.restype = c_int

nghttp2.nghttp2_session_server_new.argtypes = [POINTER(session_p), session_callbacks_p, py_object]
nghttp2.nghttp2_session_server_new.restype = c_int

nghttp2.nghttp2_session_server_new2.argtypes = [POINTER(session_p), session_callbacks_p, py_object, option_p]
nghttp2.nghttp2_session_server_new2.restype = c_int

nghttp2.nghttp2_session_del.argtypes = [session_p]

nghttp2.nghttp2_submit_settings.argtypes = [session_p, c_uint8, POINTER(settings_entry), c_size_t]
nghttp2.nghttp2_submit_settings.restype = c_int

nghttp2.nghttp2_session_get_stream_user_data.argtypes = [session_p, c_int32]
nghttp2.nghttp2_session_get_stream_user_data.restype = c_void_p

nghttp2.nghttp2_session_set_stream_user_data.argtypes = [session_p, c_int32, py_object]
nghttp2.nghttp2_session_set_stream_user_data.restype = c_int

nghttp2.nghttp2_submit_headers.argtypes = [session_p, c_uint8, c_int32, POINTER(priority_spec), POINTER(nv), c_size_t, py_object]
nghttp2.nghttp2_submit_headers.restype = c_int32

nghttp2.nghttp2_submit_data.argtypes = [session_p, c_uint8, c_int32, POINTER(data_provider)]
nghttp2.nghttp2_submit_data.restype = c_int

nghttp2.nghttp2_submit_request.argtypes = [session_p, POINTER(priority_spec), POINTER(nv), c_size_t, POINTER(data_provider), py_object]
nghttp2.nghttp2_submit_request.restype = c_int32

nghttp2.nghttp2_submit_response.argtypes = [session_p, c_int32, POINTER(nv), c_size_t, POINTER(data_provider)]
nghttp2.nghttp2_submit_response.restype = c_int

nghttp2.nghttp2_session_resume_data.argtypes = [session_p, c_int32]
nghttp2.nghttp2_session_resume_data.restype = c_int

nghttp2.nghttp2_session_terminate_session.argtypes = [session_p, c_uint32]
nghttp2.nghttp2_session_terminate_session.restype = c_int

nghttp2.nghttp2_session_send.argtypes = [session_p]
nghttp2.nghttp2_session_send.restype = c_int

nghttp2.nghttp2_session_mem_recv.argtypes = [session_p, c_char_p, c_size_t]
nghttp2.nghttp2_session_mem_recv.restype = c_ssize_t

nghttp2.nghttp2_session_mem_send.argtypes = [session_p, POINTER(POINTER(c_uint8))]
nghttp2.nghttp2_session_mem_send.restype = c_ssize_t

nghttp2.nghttp2_session_want_read.argtypes = [session_p]
nghttp2.nghttp2_session_want_read.restype = c_bool

nghttp2.nghttp2_session_want_write.argtypes = [session_p]
nghttp2.nghttp2_session_want_write.restype = c_bool

nghttp2.nghttp2_session_consume.argtypes = [session_p, c_int32, c_size_t]
nghttp2.nghttp2_session_consume.restype = c_int

nghttp2.nghttp2_session_consume_connection.argtypes = [session_p, c_size_t]
nghttp2.nghttp2_session_consume_connection.restype = c_int

nghttp2.nghttp2_session_consume_stream.argtypes = [session_p, c_int32, c_size_t]
nghttp2.nghttp2_session_consume_stream.restype = c_int

nghttp2.nghttp2_session_get_local_window_size.argtypes = [session_p]
nghttp2.nghttp2_session_get_local_window_size.restype = c_int32

nghttp2.nghttp2_session_get_stream_local_window_size.argtypes = [session_p, c_int32]
nghttp2.nghttp2_session_get_stream_local_window_size.restype = c_int32

nghttp2.nghttp2_session_get_remote_window_size.argtypes = [session_p]
nghttp2.nghttp2_session_get_remote_window_size.restype = c_int32

nghttp2.nghttp2_session_get_stream_remote_window_size.argtypes = [session_p, c_int32]
nghttp2.nghttp2_session_get_stream_remote_window_size.restype = c_int32

nghttp2.nghttp2_session_get_stream_local_close.argtypes = [session_p, c_int32]
nghttp2.nghttp2_session_get_stream_local_close.restype = c_int

nghttp2.nghttp2_session_get_stream_remote_close.argtypes = [session_p, c_int32]
nghttp2.nghttp2_session_get_stream_remote_close.restype = c_int

nghttp2.nghttp2_session_find_stream.argtypes = [session_p, c_int32]
nghttp2.nghttp2_session_find_stream.restype = stream_p


def cast_py_object(ptr):
    try:
        return cast(ptr, py_object).value
    except ValueError:
        return None


class DataStream(object):

    def __init__(self, stream):
        self.stream = stream
        self._eof = False
        self.paused = False

    def data_remaining(self):
        pos = self.stream.tell()
        byte = self.stream.read(1)
        self.stream.seek(pos)
        return len(byte) == 1

    def at_eof(self):
        return self._eof and not self.data_remaining()

    def feed_eof(self):
        self._eof = True

    def readinto(self, buf):
        return self.stream.readinto(buf)

    def write(self, data):
        # Get current position in stream
        pos = self.stream.tell()

        # Write all data to stream
        self.stream.write(data)

        # Rewind to previous position
        self.stream.seek(pos)

    def tell(self):
        return self.stream.tell()


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
