from __future__ import annotations

from ansede_static.cache import SQLiteStore, stable_hash


def test_sqlite_store_round_trip(tmp_path):
    store = SQLiteStore(tmp_path / "cache.db")
    store.set_json("scan", "doc.py", {"fingerprint": stable_hash("content"), "count": 2})

    assert store.get_json("scan", "doc.py") == {
        "fingerprint": stable_hash("content"),
        "count": 2,
    }
    assert store.keys("scan") == ["doc.py"]

    store.delete("scan", "doc.py")
    assert store.get_json("scan", "doc.py") is None
    store.close()


def test_sqlite_store_persists_between_instances(tmp_path):
    path = tmp_path / "cache.db"
    first = SQLiteStore(path)
    first.set_json("summary", "workspace", {"total": 4})
    first.close()

    second = SQLiteStore(path)
    assert second.get_json("summary", "workspace") == {"total": 4}
    second.close()