import util

def test_base64_offset():
    assert util.base64_offsets("hunter2") == [
        "aHVudGVyM",
        "h1bnRlcj",
        "odW50ZXIy",
    ]
