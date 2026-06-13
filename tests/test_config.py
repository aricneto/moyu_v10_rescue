import pytest

from moyu_v10_rescue.config import ToolConfig, norm_addr, parse_mac, suffix_from_mac


def test_norm_addr_strips_separators_and_uppercases():
    assert norm_addr("cf:30-16 01_8d:d8") == "CF3016018DD8"
    assert norm_addr(None) == ""


def test_parse_mac_accepts_common_formats():
    assert parse_mac("CF:30:16:01:8D:D8") == bytes.fromhex("cf3016018dd8")
    assert parse_mac("cf3016018dd8") == bytes.fromhex("cf3016018dd8")


def test_parse_mac_rejects_bad_lengths():
    with pytest.raises(ValueError, match="12 hex digits"):
        parse_mac("CF:30:16:01:8D")


@pytest.mark.parametrize(
    ("mac", "suffix"),
    [
        ("CF:30:16:01:8D:D8", "8DD8"),
        ("cf3016018dd8", "8DD8"),
        ("", ""),
    ],
)
def test_suffix_from_mac(mac, suffix):
    assert suffix_from_mac(mac) == suffix


def test_tool_config_identity_name_bytes():
    cfg = ToolConfig(target_name_suffix="8DD8", good_model=b"WCU_MY32")
    assert cfg.suffix_bytes == b"_8DD8"
    assert cfg.clean_name_bytes == b"WCU_MY32_8DD8"


def test_tool_config_empty_suffix_uses_just_model():
    cfg = ToolConfig(target_name_suffix="", good_model=b"WCU_MY32")
    assert cfg.suffix_bytes == b"_"
    assert cfg.clean_name_bytes == b"WCU_MY32_"
