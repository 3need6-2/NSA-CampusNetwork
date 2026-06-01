"""Test the backup utility in utils/backup.py."""

import os
import zipfile
import tempfile
from pathlib import Path
import pytest
from utils.backup import backup_data, DATA_DIR, BACKUP_DIR


@pytest.fixture
def temp_data_dir(tmp_path):
    """Create a temporary data directory with sample files."""
    data_dir = tmp_path / "data"
    data_dir.mkdir(parents=True)
    subdir = data_dir / "sub"
    subdir.mkdir()
    (data_dir / "traffic.csv").write_text("src_ip,bytes\n192.168.1.1,1024\n")
    (data_dir / "config.json").write_text('{"key": "value"}')
    (data_dir / "readme.txt").write_text("notes")
    (subdir / "nested.txt").write_text("nested content")
    return data_dir


@pytest.fixture
def monkey_backup_paths(temp_data_dir, tmp_path, monkeypatch):
    """Monkey-patch DATA_DIR and BACKUP_DIR to use temp paths."""
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir(exist_ok=True)
    from utils import backup as backup_mod
    monkeypatch.setattr(backup_mod, "DATA_DIR", temp_data_dir)
    monkeypatch.setattr(backup_mod, "BACKUP_DIR", backup_dir)
    return temp_data_dir, backup_dir


class TestBackupData:
    def test_backup_creates_zip(self, monkey_backup_paths):
        _data_dir, backup_dir = monkey_backup_paths
        result = backup_data()
        assert result.exists()
        assert result.suffix == ".zip"
        assert result.parent == backup_dir

    def test_backup_timestamp_in_name(self, monkey_backup_paths):
        result = backup_data()
        name = result.name
        assert name.startswith("data_backup_")
        assert name.endswith(".zip")
        stem = name.replace("data_backup_", "").replace(".zip", "")
        assert "_" in stem
        date_part, time_part = stem.split("_")
        assert len(date_part) == 8  # YYYYMMDD
        assert len(time_part) == 6  # HHMMSS

    def test_backup_contains_all_files(self, monkey_backup_paths):
        data_dir, _backup_dir = monkey_backup_paths
        result = backup_data()
        with zipfile.ZipFile(result, "r") as zf:
            names = zf.namelist()
        assert len(names) == 4
        assert any(n.endswith("traffic.csv") for n in names)
        assert any(n.endswith("config.json") for n in names)
        assert any(n.endswith("readme.txt") for n in names)
        assert any(n.endswith("sub/nested.txt") or n.endswith("nested.txt") for n in names)

    def test_backup_content_integrity(self, monkey_backup_paths):
        data_dir, _backup_dir = monkey_backup_paths
        result = backup_data()
        with zipfile.ZipFile(result, "r") as zf:
            for fname in ["traffic.csv", "config.json", "readme.txt"]:
                for zi in zf.infolist():
                    if zi.filename.endswith(fname):
                        content = zf.read(zi)
                        original = (data_dir / fname).read_bytes()
                        assert content == original
                        break

    def test_backup_custom_output_path(self, monkey_backup_paths):
        _data_dir, _backup_dir = monkey_backup_paths
        custom = Path(tempfile.mktemp(suffix=".zip"))
        result = backup_data(output_path=custom)
        assert result == custom
        assert custom.exists()
        custom.unlink()

    def test_backup_empty_data_dir(self, tmp_path, monkeypatch):
        empty = tmp_path / "empty_data"
        empty.mkdir()
        bk_dir = tmp_path / "backups"
        bk_dir.mkdir()
        from utils import backup as backup_mod
        monkeypatch.setattr(backup_mod, "DATA_DIR", empty)
        monkeypatch.setattr(backup_mod, "BACKUP_DIR", bk_dir)
        result = backup_data()
        assert result.exists()
        with zipfile.ZipFile(result, "r") as zf:
            assert len(zf.namelist()) == 0


class TestBackupDataErrors:
    def test_missing_data_dir_raises(self, tmp_path, monkeypatch):
        nonexistent = tmp_path / "does_not_exist"
        from utils import backup as backup_mod
        monkeypatch.setattr(backup_mod, "DATA_DIR", nonexistent)
        with pytest.raises(FileNotFoundError):
            backup_data()


class TestBackupModuleInit:
    def test_data_dir_constant(self):
        assert isinstance(DATA_DIR, Path)
        assert DATA_DIR.name == "data"

    def test_backup_dir_constant(self):
        assert isinstance(BACKUP_DIR, Path)
        assert BACKUP_DIR.name == "backups"
