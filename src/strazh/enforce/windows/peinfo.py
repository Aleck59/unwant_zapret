"""Что можно узнать о файле, не запуская его.

Два источника. Ресурс версии (`OriginalFilename`, `CompanyName`,
`ProductName`) читается дёшево и переживает переименование файла — именно
он ловит `360tray.exe`, переименованный в `svc_helper.exe`. Подпись
Authenticode надёжнее, но дороже, поэтому запрашивается отдельно и только
когда дешёвые признаки не сработали.

Всё сделано на ctypes: тянуть pywin32 ради двух вызовов не стоит, а лишняя
зависимость в программе, которая работает с правами системы, — плохой обмен.
"""

from __future__ import annotations

import ctypes
import sys
from ctypes import wintypes
from dataclasses import dataclass

IS_WINDOWS = sys.platform == "win32"


@dataclass(frozen=True, slots=True)
class VersionInfo:
    original_filename: str | None = None
    company_name: str | None = None
    product_name: str | None = None
    file_description: str | None = None


_EMPTY = VersionInfo()

if IS_WINDOWS:  # pragma: no cover - весь модуль имеет смысл только в Windows
    _version = ctypes.WinDLL("version.dll", use_last_error=True)
    _crypt32 = ctypes.WinDLL("crypt32.dll", use_last_error=True)

    _version.GetFileVersionInfoSizeW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(wintypes.DWORD)]
    _version.GetFileVersionInfoSizeW.restype = wintypes.DWORD
    _version.GetFileVersionInfoW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
    ]
    _version.GetFileVersionInfoW.restype = wintypes.BOOL
    _version.VerQueryValueW.argtypes = [
        ctypes.c_void_p,
        wintypes.LPCWSTR,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.UINT),
    ]
    _version.VerQueryValueW.restype = wintypes.BOOL

    # Возвращаемые указатели обязаны быть объявлены: без restype ctypes
    # считает результат 32-разрядным int и на 64 битах отрезает половину
    # адреса — обращение по такому «указателю» роняет процесс.
    _crypt32.CryptQueryObject.restype = wintypes.BOOL
    _crypt32.CryptMsgGetParam.restype = wintypes.BOOL
    _crypt32.CryptMsgClose.restype = wintypes.BOOL
    _crypt32.CertCloseStore.restype = wintypes.BOOL
    _crypt32.CertFindCertificateInStore.restype = ctypes.c_void_p
    _crypt32.CertFreeCertificateContext.restype = wintypes.BOOL
    _crypt32.CertFreeCertificateContext.argtypes = [ctypes.c_void_p]
    _crypt32.CertGetNameStringW.restype = wintypes.DWORD
    _crypt32.CertGetNameStringW.argtypes = [
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.LPWSTR,
        wintypes.DWORD,
    ]


def version_info(path: str) -> VersionInfo:
    """Ресурс версии файла. Пустой результат — обычное дело для многих файлов."""
    if not IS_WINDOWS:
        return _EMPTY
    try:  # pragma: no cover
        handle = wintypes.DWORD(0)
        size = _version.GetFileVersionInfoSizeW(path, ctypes.byref(handle))
        if not size:
            return _EMPTY
        buffer = ctypes.create_string_buffer(size)
        if not _version.GetFileVersionInfoW(path, 0, size, buffer):
            return _EMPTY

        # Файл может нести несколько языковых блоков; берём первый — все
        # интересующие нас поля в них совпадают.
        block = ctypes.c_void_p()
        length = wintypes.UINT()
        if not _version.VerQueryValueW(
            buffer, "\\VarFileInfo\\Translation", ctypes.byref(block), ctypes.byref(length)
        ):
            return _EMPTY
        if length.value < 4:
            return _EMPTY
        pair = ctypes.cast(block, ctypes.POINTER(wintypes.WORD))
        lang, codepage = pair[0], pair[1]
        prefix = f"\\StringFileInfo\\{lang:04x}{codepage:04x}\\"

        def field(name: str) -> str | None:
            value = ctypes.c_void_p()
            size_out = wintypes.UINT()
            if not _version.VerQueryValueW(
                buffer, prefix + name, ctypes.byref(value), ctypes.byref(size_out)
            ):
                return None
            text = ctypes.wstring_at(value, size_out.value).strip("\x00").strip()
            return text or None

        return VersionInfo(
            original_filename=field("OriginalFilename"),
            company_name=field("CompanyName"),
            product_name=field("ProductName"),
            file_description=field("FileDescription"),
        )
    except (OSError, ValueError):
        return _EMPTY


# ── подпись Authenticode ──────────────────────────────────────────────────────

_CERT_QUERY_OBJECT_FILE = 0x00000001
_CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED = 1 << 10
_CERT_QUERY_FORMAT_FLAG_BINARY = 1 << 1
_CMSG_SIGNER_INFO_PARAM = 6
_CERT_FIND_SUBJECT_CERT = 0x000B0000
_X509_ASN_ENCODING = 0x00000001
_PKCS_7_ASN_ENCODING = 0x00010000
_ENCODING = _X509_ASN_ENCODING | _PKCS_7_ASN_ENCODING
_CERT_NAME_SIMPLE_DISPLAY_TYPE = 4


class _CryptoapiBlob(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]


class _CryptAlgorithmIdentifier(ctypes.Structure):
    _fields_ = [("pszObjId", ctypes.c_char_p), ("Parameters", _CryptoapiBlob)]


class _CertInfo(ctypes.Structure):
    _fields_ = [
        ("dwVersion", wintypes.DWORD),
        ("SerialNumber", _CryptoapiBlob),
        ("SignatureAlgorithm", _CryptAlgorithmIdentifier),
        ("Issuer", _CryptoapiBlob),
        ("NotBefore", wintypes.FILETIME),
        ("NotAfter", wintypes.FILETIME),
        ("Subject", _CryptoapiBlob),
    ]


class _CmsgSignerInfo(ctypes.Structure):
    _fields_ = [
        ("dwVersion", wintypes.DWORD),
        ("Issuer", _CryptoapiBlob),
        ("SerialNumber", _CryptoapiBlob),
        ("HashAlgorithm", _CryptAlgorithmIdentifier),
        ("HashEncryptionAlgorithm", _CryptAlgorithmIdentifier),
        ("EncryptedHash", _CryptoapiBlob),
        ("AuthAttrs", _CryptoapiBlob),
        ("UnauthAttrs", _CryptoapiBlob),
    ]


def signature_subject(path: str) -> str | None:
    """Кому выдан сертификат, которым подписан файл.

    Возвращает `None`, если подписи нет или её не удалось разобрать. Проверка
    доверия к цепочке здесь не делается намеренно: нас интересует имя, а не
    действительность — отозванный сертификат Qihoo остаётся сертификатом Qihoo.
    """
    if not IS_WINDOWS:
        return None
    try:  # pragma: no cover - разбирается только на Windows
        store = ctypes.c_void_p()
        message = ctypes.c_void_p()
        ok = _crypt32.CryptQueryObject(
            _CERT_QUERY_OBJECT_FILE,
            ctypes.c_wchar_p(path),
            _CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
            _CERT_QUERY_FORMAT_FLAG_BINARY,
            0,
            None,
            None,
            None,
            ctypes.byref(store),
            ctypes.byref(message),
            None,
        )
        if not ok:
            return None
        try:
            size = wintypes.DWORD()
            if not _crypt32.CryptMsgGetParam(
                message, _CMSG_SIGNER_INFO_PARAM, 0, None, ctypes.byref(size)
            ):
                return None
            buffer = ctypes.create_string_buffer(size.value)
            if not _crypt32.CryptMsgGetParam(
                message, _CMSG_SIGNER_INFO_PARAM, 0, buffer, ctypes.byref(size)
            ):
                return None
            signer = ctypes.cast(buffer, ctypes.POINTER(_CmsgSignerInfo)).contents

            info = _CertInfo()
            info.Issuer = signer.Issuer
            info.SerialNumber = signer.SerialNumber
            cert = _crypt32.CertFindCertificateInStore(
                store, _ENCODING, 0, _CERT_FIND_SUBJECT_CERT, ctypes.byref(info), None
            )
            cert = ctypes.c_void_p(cert) if cert else None
            if cert is None:
                return None
            try:
                length = _crypt32.CertGetNameStringW(
                    cert, _CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, None, None, 0
                )
                if length <= 1:
                    return None
                name = ctypes.create_unicode_buffer(length)
                _crypt32.CertGetNameStringW(
                    cert, _CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, None, name, length
                )
                return name.value or None
            finally:
                _crypt32.CertFreeCertificateContext(cert)
        finally:
            if message:
                _crypt32.CryptMsgClose(message)
            if store:
                _crypt32.CertCloseStore(store, 0)
    except (OSError, ValueError, AttributeError):
        return None
