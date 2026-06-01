from utils.constants import (
    SENSITIVE_PORTS,
    SUSPICIOUS_PORTS,
    PROMPT_INJECTION_TERMS,
    AI_AGENT_TERMS,
    WEB_ATTACK_TERMS,
    NORMALIZED_CATEGORIES,
    FEATURE_NAMES,
    USER_PROFILE_SUSPICIOUS_PORTS,
    REALTIME_WINDOW_SIZE,
    ML_MIN_USERS,
    ML_DEFAULT_CONTAMINATION,
    ML_TOP_N,
)


def test_sensitive_ports_types():
    assert isinstance(SENSITIVE_PORTS, dict)
    assert len(SENSITIVE_PORTS) > 0
    for port, name in SENSITIVE_PORTS.items():
        assert isinstance(port, int)
        assert isinstance(name, str)
        assert len(name) > 0
        assert port > 0


def test_suspicious_ports_types():
    assert isinstance(SUSPICIOUS_PORTS, set)
    assert len(SUSPICIOUS_PORTS) > 0
    for port in SUSPICIOUS_PORTS:
        assert isinstance(port, int)
        assert port > 0


def test_prompt_injection_terms():
    assert isinstance(PROMPT_INJECTION_TERMS, list)
    assert len(PROMPT_INJECTION_TERMS) > 0
    for term in PROMPT_INJECTION_TERMS:
        assert isinstance(term, str)
        assert len(term) > 0


def test_ai_agent_terms():
    assert isinstance(AI_AGENT_TERMS, list)
    assert len(AI_AGENT_TERMS) > 0
    for term in AI_AGENT_TERMS:
        assert isinstance(term, str)
        assert len(term) > 0


def test_web_attack_terms():
    assert isinstance(WEB_ATTACK_TERMS, list)
    assert len(WEB_ATTACK_TERMS) > 0
    for term in WEB_ATTACK_TERMS:
        assert isinstance(term, str)
        assert len(term) > 0


def test_normalized_categories():
    assert isinstance(NORMALIZED_CATEGORIES, dict)
    assert len(NORMALIZED_CATEGORIES) > 0
    for category, aliases in NORMALIZED_CATEGORIES.items():
        assert isinstance(category, str)
        assert isinstance(aliases, list)
        assert len(aliases) > 0
        for alias in aliases:
            assert isinstance(alias, str)
            assert len(alias) > 0


def test_feature_names():
    assert isinstance(FEATURE_NAMES, list)
    assert len(FEATURE_NAMES) > 0
    for name in FEATURE_NAMES:
        assert isinstance(name, str)
        assert len(name) > 0


def test_user_profile_suspicious_ports():
    assert isinstance(USER_PROFILE_SUSPICIOUS_PORTS, list)
    assert len(USER_PROFILE_SUSPICIOUS_PORTS) > 0
    for port in USER_PROFILE_SUSPICIOUS_PORTS:
        assert isinstance(port, int)
        assert port > 0


def test_realtime_constants():
    assert isinstance(REALTIME_WINDOW_SIZE, int)
    assert REALTIME_WINDOW_SIZE > 0


def test_ml_constants():
    assert isinstance(ML_MIN_USERS, int)
    assert ML_MIN_USERS > 0
    assert isinstance(ML_DEFAULT_CONTAMINATION, float)
    assert 0 < ML_DEFAULT_CONTAMINATION <= 1
    assert isinstance(ML_TOP_N, int)
    assert ML_TOP_N > 0
