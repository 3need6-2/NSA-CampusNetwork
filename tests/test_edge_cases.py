import pytest
import pandas as pd
from io import StringIO


class TestEmptyDataFrame:

    def test_analyzer_empty_csv(self, empty_df):
        from utils.analysis import TrafficAnalyzer
        with pytest.raises(Exception):
            TrafficAnalyzer("/nonexistent/path.csv")

    def test_get_total_traffic_empty(self):
        import tempfile, os
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
            f.write("timestamp,src_ip,dst_ip,src_port,dst_port,protocol,bytes,app_category,user\n")
            tmp = f.name
        try:
            from utils.analysis import TrafficAnalyzer
            analyzer = TrafficAnalyzer(tmp)
            stats = analyzer.get_total_traffic()
            assert stats["total_bytes"] == 0
            assert stats["unique_users"] == 0
        finally:
            os.unlink(tmp)

    def test_get_heatmap_data_empty(self, empty_df):
        from utils.analysis import TrafficAnalyzer
        analyzer = TrafficAnalyzer.__new__(TrafficAnalyzer)
        analyzer.df = empty_df
        analyzer.csv_path = ""
        result = analyzer.get_heatmap_data()
        assert result == []

    def test_get_anomaly_timeline_empty(self, empty_df):
        from utils.analysis import TrafficAnalyzer
        analyzer = TrafficAnalyzer.__new__(TrafficAnalyzer)
        analyzer.df = empty_df
        analyzer.csv_path = ""
        result = analyzer.get_anomaly_timeline()
        assert result == []

    def test_get_comparison_empty(self, empty_df):
        from utils.analysis import TrafficAnalyzer
        analyzer = TrafficAnalyzer.__new__(TrafficAnalyzer)
        analyzer.df = empty_df
        analyzer.csv_path = ""
        result = analyzer.get_comparison("a", "b")
        assert result == {}


class TestMissingColumns:

    def test_missing_bytes_column(self):
        import tempfile, os
        bad_csv = "timestamp,user,app_category\n2025-01-01,test,web\n"
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
            f.write(bad_csv)
            tmp = f.name
        try:
            from utils.analysis import TrafficAnalyzer
            analyzer = TrafficAnalyzer(tmp)
            assert analyzer.df is None or 'bytes' not in analyzer.df.columns
        finally:
            os.unlink(tmp)

    def test_missing_timestamp(self):
        import tempfile, os
        bad_csv = "src_ip,dst_ip,protocol,bytes,user\n192.168.1.1,8.8.8.8,TCP,512,test\n"
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
            f.write(bad_csv)
            tmp = f.name
        try:
            from utils.analysis import TrafficAnalyzer
            analyzer = TrafficAnalyzer(tmp)
            assert analyzer.df is None or 'timestamp' not in analyzer.df.columns
        finally:
            os.unlink(tmp)


class TestMalformedData:

    def test_non_numeric_bytes(self):
        import tempfile, os
        bad_csv = "timestamp,src_ip,dst_ip,src_port,dst_port,protocol,bytes,app_category,user\n2025-01-01 08:00:00,1.1.1.1,2.2.2.2,80,80,TCP,notanumber,Web,test\n"
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
            f.write(bad_csv)
            tmp = f.name
        try:
            from utils.analysis import TrafficAnalyzer
            analyzer = TrafficAnalyzer(tmp)
            stats = analyzer.get_total_traffic()
            assert stats is not None
        finally:
            os.unlink(tmp)

    def test_empty_file(self):
        import tempfile, os
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
            f.write("")
            tmp = f.name
        try:
            from utils.analysis import TrafficAnalyzer
            analyzer = TrafficAnalyzer(tmp)
            assert analyzer.df is None or len(analyzer.df) == 0
        finally:
            os.unlink(tmp)

    def test_header_only_csv(self):
        import tempfile, os
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
            f.write("timestamp,src_ip,dst_ip,src_port,dst_port,protocol,bytes,app_category,user\n")
            tmp = f.name
        try:
            from utils.analysis import TrafficAnalyzer
            analyzer = TrafficAnalyzer(tmp)
            stats = analyzer.get_total_traffic()
            assert stats["total_bytes"] == 0
        finally:
            os.unlink(tmp)
