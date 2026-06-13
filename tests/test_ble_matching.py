from types import SimpleNamespace

import pytest

pytest.importorskip("bleak")

from moyu_v10_rescue.config import ToolConfig
from moyu_v10_rescue.cube_ble import FoundDevice, looks_like_target


def dev(address="00:00:00:00:00:00", name=None):
    return SimpleNamespace(address=address, name=name)


def adv(local_name=None, rssi=-50, service_uuids=None, manufacturer_data=None):
    return SimpleNamespace(
        local_name=local_name,
        rssi=rssi,
        service_uuids=service_uuids or [],
        manufacturer_data=manufacturer_data or {},
    )


def test_looks_like_target_matches_exact_address():
    cfg = ToolConfig(target_address="CF:30:16:01:8D:D8", target_name_suffix="8DD8")
    assert looks_like_target(dev("CF:30:16:01:8D:D8"), adv(), cfg)


def test_looks_like_target_matches_visible_name_suffix():
    cfg = ToolConfig(target_address="", target_name_suffix="8DD8")
    assert looks_like_target(dev("AA:BB:CC:DD:EE:FF", name='"��`��S_8DD8'), adv(), cfg)
    assert looks_like_target(dev("AA:BB:CC:DD:EE:FF"), adv(local_name="WCU_MY32_8DD8"), cfg)


def test_looks_like_target_matches_address_suffix_when_name_is_missing():
    cfg = ToolConfig(target_address="", target_name_suffix="8DD8")
    assert looks_like_target(dev("CF:30:16:01:8D:D8"), adv(), cfg)


def test_looks_like_target_rejects_unrelated_device():
    cfg = ToolConfig(target_address="CF:30:16:01:8D:D8", target_name_suffix="8DD8")
    assert not looks_like_target(dev("AA:BB:CC:DD:EE:FF", name="keyboard"), adv(local_name="mouse"), cfg)


def test_found_device_properties_join_names_and_handle_none():
    fd = FoundDevice(dev("CF:30:16:01:8D:D8", name=None), adv(local_name="WCU_MY32_8DD8", rssi=-42))
    assert fd.address == "CF:30:16:01:8D:D8"
    assert fd.name == ""
    assert fd.local_name == "WCU_MY32_8DD8"
    assert fd.all_names == "WCU_MY32_8DD8"
    assert fd.rssi == -42
