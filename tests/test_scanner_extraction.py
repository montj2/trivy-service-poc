import pytest
from pathlib import Path
import tarfile
import zipfile
import shutil
import tempfile
from app.services.scanner import extract_archive

@pytest.fixture
def temp_dirs():
    temp_dir = tempfile.mkdtemp()
    target_dir = tempfile.mkdtemp()
    yield Path(temp_dir), Path(target_dir)
    shutil.rmtree(temp_dir)
    shutil.rmtree(target_dir)

def test_extract_archive_tgz(temp_dirs):
    src_dir, target_dir = temp_dirs
    # Create dummy file
    (src_dir / "foo.txt").write_text("bar")
    
    # Create tar.gz
    archive = src_dir / "test.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        tar.add(src_dir / "foo.txt", arcname="foo.txt")
        
    assert extract_archive(archive, target_dir) is True
    assert (target_dir / "foo.txt").exists()
    assert (target_dir / "foo.txt").read_text() == "bar"

def test_extract_archive_zip_whl(temp_dirs):
    src_dir, target_dir = temp_dirs
    (src_dir / "foo.txt").write_text("bar")
    
    # Create zip (whl)
    archive = src_dir / "test.whl"
    with zipfile.ZipFile(archive, "w") as z:
        z.write(src_dir / "foo.txt", arcname="foo.txt")
        
    assert extract_archive(archive, target_dir) is True
    assert (target_dir / "foo.txt").exists()

def test_extract_archive_invalid_format(temp_dirs):
    src_dir, target_dir = temp_dirs
    archive = src_dir / "test.txt"
    archive.write_text("not an archive")
    
    assert extract_archive(archive, target_dir) is False

def test_extract_archive_corrupt_tar(temp_dirs):
    src_dir, target_dir = temp_dirs
    archive = src_dir / "corrupt.tar.gz"
    archive.write_bytes(b"not a tar")
    
    assert extract_archive(archive, target_dir) is False
