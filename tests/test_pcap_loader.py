"""
Unit tests for upload validation, capture header detection, and tshark checks.
"""

from core.pcap_loader import (
    detect_capture_format,
    validate_capture_bytes,
    validate_capture_file,
    check_tshark_available
)
from core.config import AppConfig


def test_detect_capture_format():
    assert detect_capture_format(b"\xa1\xb2\xc3\xd4") == "pcap"
    assert detect_capture_format(b"\xd4\xc3\xb2\xa1") == "pcap"
    assert detect_capture_format(b"\x0a\x0d\x0d\x0a") == "pcapng"
    assert detect_capture_format(b"GIF89a") is None
    assert detect_capture_format(b"") is None


def test_validate_capture_bytes_empty():
    res = validate_capture_bytes(b"", "test.pcap")
    assert not res.is_valid
    assert "empty" in res.error_message.lower()


def test_validate_capture_bytes_invalid_ext():
    res = validate_capture_bytes(b"\xa1\xb2\xc3\xd4\x00\x00", "test.exe")
    assert not res.is_valid
    assert "extension" in res.error_message.lower()


def test_validate_capture_bytes_valid_pcap():
    valid_bytes = b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00" + b"\x00" * 30
    res = validate_capture_bytes(valid_bytes, "test.pcap")
    assert res.is_valid
    assert res.file_type == "pcap"


def test_validate_capture_file(tmp_path):
    # 1. Non-existent file
    res = validate_capture_file(str(tmp_path / "does_not_exist.pcap"))
    assert not res.is_valid
    assert "not exist" in res.error_message.lower()

    # 2. Empty file
    empty_f = tmp_path / "empty.pcap"
    empty_f.write_bytes(b"")
    res = validate_capture_file(str(empty_f))
    assert not res.is_valid
    assert "empty" in res.error_message.lower()

    # 3. Invalid extension
    exe_f = tmp_path / "test.exe"
    exe_f.write_bytes(b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00")
    res = validate_capture_file(str(exe_f))
    assert not res.is_valid
    assert "extension" in res.error_message.lower()

    # 4. Text masquerading as .pcap (invalid magic bytes)
    fake_f = tmp_path / "fake.pcap"
    fake_f.write_text("This is just a text file not a pcap")
    res = validate_capture_file(str(fake_f))
    assert not res.is_valid
    assert "signature" in res.error_message.lower() or "header" in res.error_message.lower()

    # 5. Real valid PCAP
    res = validate_capture_file("sample_pcaps/normal_traffic.pcap")
    assert res.is_valid
    assert res.file_type == "pcap"


def test_tshark_availability():
    is_avail, info = check_tshark_available()
    assert is_avail is True
    assert "TShark" in info or "4." in info

