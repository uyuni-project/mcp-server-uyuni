import json

from test_tool_catalog import snapshot


def test_snapshot_schema_sizes_and_safe_content():
    baseline = json.loads(snapshot.BASELINE.read_text())
    for catalog in baseline["catalogs"]:
        sizes = []
        for tool in catalog["tools"]:
            entry = {key: value for key, value in tool.items() if key != "serialized_schema_bytes"}
            size = len(snapshot._json(entry).encode("utf-8"))
            assert tool["serialized_schema_bytes"] == size
            assert tool["input_schema"]
            sizes.append(size)
        assert catalog["serialized_schema_bytes"] == sum(sizes)
    serialized = snapshot.BASELINE.read_text()
    assert "baseline.invalid" not in serialized
    assert '"baseline"' not in serialized
