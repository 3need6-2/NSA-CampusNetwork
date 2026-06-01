from utils.realtime import ReplayEngine, sse_format
import pandas as pd
import json


def test_engine_singleton():
    e1 = ReplayEngine.instance()
    e2 = ReplayEngine.instance()
    assert e1 is e2


def test_start_with_empty_dataframe():
    engine = ReplayEngine.instance()
    result = engine.start(pd.DataFrame())
    assert result["status"] == "error"


def test_start_and_stop(sample_df):
    engine = ReplayEngine.instance()
    engine.stop()
    result = engine.start(sample_df, rate=10.0, loop=False)
    assert result["status"] == "started"
    status = engine.status()
    assert status["running"] is True
    engine.stop()
    status = engine.status()
    assert status["running"] is False


def test_set_rate(sample_df):
    engine = ReplayEngine.instance()
    engine.stop()
    engine.start(sample_df, rate=5.0, loop=False)
    result = engine.set_rate(20.0)
    assert result["status"] == "ok"
    assert result["rate"] == 20.0
    engine.stop()


def test_status_format(sample_df):
    engine = ReplayEngine.instance()
    engine.stop()
    engine.start(sample_df, rate=5.0, loop=False)
    status = engine.status()
    assert "running" in status
    assert "rate" in status
    assert "metrics" in status
    assert "subscribers" in status
    engine.stop()


def test_subscribe_unsubscribe():
    engine = ReplayEngine.instance()
    q = engine.subscribe()
    assert q is not None
    engine.unsubscribe(q)


def test_sse_format():
    msg = {"type": "test", "payload": {"key": "value"}}
    result = sse_format(msg)
    assert "event: test" in result
    assert '"key": "value"' in result


def test_double_start(sample_df):
    engine = ReplayEngine.instance()
    engine.stop()
    engine.start(sample_df, rate=10.0, loop=False)
    result = engine.start(sample_df, rate=10.0, loop=False)
    assert result["status"] == "already_running"
    engine.stop()
