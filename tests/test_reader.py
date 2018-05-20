from pynghttp2 import StreamReader


def test_streaming():
    chunk = bytearray(1024)

    reader = StreamReader()

    reader.feed_data(chunk)
    reader.feed_data(chunk)

    assert len(reader.read_nowait(256)) == 256
    assert len(reader.read_nowait(512)) == 512
    assert len(reader.read_nowait(1024)) == 1024
    assert len(reader.read_nowait(-1)) == 256

    reader.feed_data(chunk)
    assert len(reader.read_nowait(256)) == 256

    reader.feed_eof()
    assert reader.at_eof() == False
    assert reader.is_eof() == True

    assert len(reader.read_nowait(2048)) == 1024 - 256
    assert reader.at_eof() == True