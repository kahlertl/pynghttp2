from ctypes import *
from .typedefs import *


nghttp2 = CDLL('libnghttp2.so')


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


nghttp2.nghttp2_version.argtypes = [c_int]
nghttp2.nghttp2_version.restype = POINTER(info)



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
