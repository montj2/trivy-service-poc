import pytest
from pathlib import Path
from app.services.engine import ScanEngine
from app.api.models import ScanCounts, Recommendation

def test_path_validation_success(tmp_path):
    # Setup allowed root
    engine = ScanEngine()
    # Mock settings to allow tmp_path
    from app.core import config
    config.settings.ALLOWED_SCAN_ROOTS = str(tmp_path)
    
    test_file = tmp_path / "test.bin"
    test_file.touch()
    
    assert engine._validate_path(str(test_file)) == test_file.resolve()

def test_path_validation_failure_not_allowed(tmp_path):
    engine = ScanEngine()
    # root is default -> /mnt/artifacts
    test_file = tmp_path / "test.bin"
    test_file.touch()
    
    with pytest.raises(ValueError, match="Path is not within allowed scan roots"):
        engine._validate_path(str(test_file))

def test_decision_logic_block_critical():
    engine = ScanEngine()
    counts = ScanCounts()
    counts.vulnerabilities.CRITICAL = 1
    
    decision = engine._make_decision(counts)
    assert decision.recommendation == Recommendation.BLOCK
    assert "CRITICAL" in decision.reasons[0]

def test_decision_logic_block_secrets():
    engine = ScanEngine()
    counts = ScanCounts()
    counts.secrets = 1
    
    decision = engine._make_decision(counts)
    assert decision.recommendation == Recommendation.BLOCK
    assert "secrets" in decision.reasons[0]

def test_decision_logic_review_high():
    engine = ScanEngine()
    counts = ScanCounts()
    counts.vulnerabilities.HIGH = 1
    
    decision = engine._make_decision(counts)
    assert decision.recommendation == Recommendation.REVIEW
    assert "HIGH" in decision.reasons[0]

def test_decision_logic_allow():
    engine = ScanEngine()
    counts = ScanCounts()
    
    decision = engine._make_decision(counts)
    assert decision.recommendation == Recommendation.ALLOW

def test_path_validation_symlink_failure(tmp_path):
    engine = ScanEngine()
    from app.core import config
    config.settings.ALLOWED_SCAN_ROOTS = str(tmp_path)
    
    target = tmp_path / "target.txt"
    target.touch()
    
    link = tmp_path / "link.txt"
    link.symlink_to(target)
    
    with pytest.raises(ValueError, match="Symlinks are not allowed"):
        engine._validate_path(str(link))
