"""Tests for resolver safety checks."""

from aigate.resolver import _extract_archive, _is_path_safe


class TestPathSafe:
    def test_normal_path(self):
        assert _is_path_safe("package-1.0/src/main.py") is True

    def test_path_traversal_dotdot(self):
        assert _is_path_safe("../../etc/passwd") is False

    def test_path_traversal_mid(self):
        assert _is_path_safe("package-1.0/../../../secret") is False

    def test_absolute_path(self):
        assert _is_path_safe("/etc/passwd") is False

    def test_empty_path(self):
        assert _is_path_safe("") is False

    def test_single_dot(self):
        # "." is fine (current dir reference in archives)
        assert _is_path_safe("./src/main.py") is True

    def test_dotdot_in_name(self):
        # "some..file" is fine, ".." as a directory component is not
        assert _is_path_safe("package/some..file.py") is True


class TestExtractArchive:
    def test_empty_content(self):
        result = _extract_archive(b"", "test.tar.gz")
        assert result == {}

    def test_unsupported_format(self):
        result = _extract_archive(b"data", "test.rpm")
        assert result == {}
