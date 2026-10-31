import main
import pytest
from fastapi import HTTPException


def test_rejects_fake_pdf():
    with pytest.raises(HTTPException) as exc:
        main.extract("fake.pdf", b"This is not a PDF file")
    assert exc.value.status_code == 415


def test_rejects_fake_docx():
    with pytest.raises(HTTPException) as exc:
        main.extract("fake.docx", b"This is not a DOCX file")
    assert exc.value.status_code == 415


def test_rejects_invalid_utf8_text():
    with pytest.raises(HTTPException) as exc:
        main.extract("invalid.txt", b"\xff\xfe\xfa")
    assert exc.value.status_code == 422


def test_rejects_unsupported_extension():
    with pytest.raises(HTTPException) as exc:
        main.extract("payload.exe", b"example")
    assert exc.value.status_code == 415


def test_accepts_valid_utf8_text():
    result = main.extract(
        "safe.txt",
        b"Employees must request leave through HR."
    )
    assert "request leave through HR" in result


def test_enforces_extracted_text_limit(monkeypatch):
    monkeypatch.setattr(main, "MAX_TEXT_CHARS", 5)

    with pytest.raises(HTTPException) as exc:
        main.extract("large.txt", b"123456")

    assert exc.value.status_code == 413
