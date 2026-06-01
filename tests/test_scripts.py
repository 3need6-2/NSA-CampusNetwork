import pytest
import sys
import os
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


def test_export_report_importable():
    from scripts.export_report import export_report
    assert callable(export_report)


def test_import_data_importable():
    from scripts.import_data import import_data
    assert callable(import_data)


def test_cleanup_importable():
    from scripts.cleanup import cleanup
    assert callable(cleanup)


def test_export_report_runs(sample_csv_path):
    from scripts.export_report import export_report
    with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
        out_path = f.name
    try:
        export_report(sample_csv_path, out_path)
        assert os.path.exists(out_path)
        content = Path(out_path).read_text()
        assert "<html>" in content
        assert "Traffic Analysis Report" in content
    finally:
        if os.path.exists(out_path):
            os.unlink(out_path)


def test_import_data_runs(sample_csv_path):
    from scripts.import_data import import_data
    import_data(sample_csv_path)


def test_cleanup_dry_run():
    from scripts.cleanup import cleanup
    cleanup(days=1, dry_run=True)


@pytest.fixture
def sample_csv_path():
    content = """\
timestamp,src_ip,dst_ip,src_port,dst_port,protocol,bytes,app_category,user
2025-12-01 08:00:15,192.168.1.100,8.8.8.8,52341,53,UDP,256,DNS,student_001
2025-12-01 08:00:32,192.168.1.101,142.251.41.14,52456,443,TCP,4096,Social Media,student_002
"""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
        f.write(content)
        tmp_path = f.name
    yield tmp_path
    if os.path.exists(tmp_path):
        os.unlink(tmp_path)
