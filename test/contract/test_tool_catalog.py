import importlib.util
from pathlib import Path


SNAPSHOT_PATH = Path(__file__).with_name("catalog_snapshot.py")
spec = importlib.util.spec_from_file_location("catalog_snapshot", SNAPSHOT_PATH)
snapshot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(snapshot)


def test_legacy_catalog_snapshot_is_deterministic():
    expected = snapshot.BASELINE.read_text()
    assert snapshot.serialized_baseline() == expected
    assert snapshot.serialized_baseline() == expected


def test_legacy_catalog_names_and_write_state():
    read_only, write_enabled = snapshot.generate()["catalogs"]
    read_names = [tool["name"] for tool in read_only["tools"]]
    write_names = [tool["name"] for tool in write_enabled["tools"]]
    assert read_only["write_enabled"] is False
    assert write_enabled["write_enabled"] is True
    assert read_only["tool_count"] == 18
    assert write_enabled["tool_count"] == 27
    assert write_names[:11] == read_names[:11]
    assert set(read_names).issubset(write_names)
