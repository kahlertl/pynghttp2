"""Type definitions compatible with the libnghttp2 API"""
import enum
from ctypes import *


__all__ = [
    'session_p',
    'stream_p',
    'option_p',
    'session_callbacks_p',
    'error',
    'error_code',
    'data_flag',
    'nv_flag',
    'frame_type',
    'flag',
    'settings_id',
    'headers_category',
    'hd_inflate_flag',
    'stream_proto_state',
    'info',
    'frame_hd',
    'data_source',
    'data_source_read_callback',
    'data_provider',
    'data',
    'priority_spec',
    'nv',
    'headers',
    'priority',
    'rst_stream',
    'settings_entry',
    'settings',
    'push_promise',
    'ping',
    'goaway',
    'window_update',
    'extension',
    'frame',
    'send_callback',
    'send_data_callback',
    'on_frame_recv_callback',
    'on_frame_send_callback',
    'on_data_chunk_recv_callback',
    'on_stream_close_callback',
    'on_header_callback',
    'on_begin_headers_callback',
]


# Pointers to opaque structs
session_p = c_void_p
stream_p = c_void_p
option_p = c_void_p
session_callbacks_p = c_void_p


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

    Attributes:
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

    Attributes:
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

    Attributes:
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

    Attributes:
        padlen (size_t):
            The length of the padding in this frame. This includes PAD_HIGH and
            PAD_LOW.
    """
    _fields_ = [
        ('padlen', c_size_t),
    ]


class priority_spec(Structure):
    """The structure to specify stream dependency

    Attributes:
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

    Attributes:
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

    Attributes:
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

    Attributes:
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

    Attributes:
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

    Attributes:
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

    Attributes:
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

    Attributes:
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

    Attributes:
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

    Attributes:
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

    Attributes:
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

    Attributes:
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


# Session callback types
send_callback = CFUNCTYPE(c_ssize_t, session_p, POINTER(c_uint8), c_size_t, c_int, py_object)
send_data_callback = CFUNCTYPE(c_int, session_p, POINTER(frame), POINTER(c_uint8), c_size_t, POINTER(data_source), py_object)
on_frame_recv_callback = CFUNCTYPE(c_int, session_p, POINTER(frame), py_object)
on_frame_send_callback = CFUNCTYPE(c_int, session_p, POINTER(frame), py_object)
on_data_chunk_recv_callback = CFUNCTYPE(c_int, session_p, c_uint8, c_int32, POINTER(c_uint8), c_size_t, py_object)
on_stream_close_callback = CFUNCTYPE(c_int, session_p, c_int32, c_uint32, py_object)
on_header_callback = CFUNCTYPE(c_int, session_p, POINTER(frame), POINTER(c_uint8), c_size_t, POINTER(c_uint8), c_size_t, c_uint8, py_object)
on_begin_headers_callback = CFUNCTYPE(c_int, session_p, POINTER(frame), py_object)
