"""Перечисление и снятие процессов.

Только ctypes: снимок процессов через Toolhelp даёт имя и номер, полный путь
добирается отдельно и мягко — часть процессов системы не откроется даже
администратору, и это не ошибка, а норма.
"""

from __future__ import annotations

import ctypes
import sys
from ctypes import wintypes
from dataclasses import dataclass

IS_WINDOWS = sys.platform == "win32"

TH32CS_SNAPPROCESS = 0x00000002
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_TERMINATE = 0x0001
MAX_PATH = 260


@dataclass(frozen=True, slots=True)
class ProcessEntry:
    pid: int
    name: str
    path: str | None = None
    parent_pid: int = 0


if IS_WINDOWS:  # pragma: no cover - только Windows

    class _ProcessEntry32W(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("cntUsage", wintypes.DWORD),
            ("th32ProcessID", wintypes.DWORD),
            ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
            ("th32ModuleID", wintypes.DWORD),
            ("cntThreads", wintypes.DWORD),
            ("th32ParentProcessID", wintypes.DWORD),
            ("pcPriClassBase", ctypes.c_long),
            ("dwFlags", wintypes.DWORD),
            ("szExeFile", wintypes.WCHAR * MAX_PATH),
        ]

    _kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)
    _kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    _kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    _kernel32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(_ProcessEntry32W)]
    _kernel32.Process32FirstW.restype = wintypes.BOOL
    _kernel32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(_ProcessEntry32W)]
    _kernel32.Process32NextW.restype = wintypes.BOOL
    _kernel32.OpenProcess.restype = wintypes.HANDLE
    _kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    _kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    _kernel32.CloseHandle.restype = wintypes.BOOL
    _kernel32.QueryFullProcessImageNameW.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD),
    ]
    _kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
    _kernel32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    _kernel32.TerminateProcess.restype = wintypes.BOOL

    _INVALID_HANDLE = wintypes.HANDLE(-1).value


def image_path(pid: int) -> str | None:
    """Полный путь к файлу процесса или `None`, если доступа не хватило."""
    if not IS_WINDOWS:
        return None
    handle = _kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return None
    try:
        size = wintypes.DWORD(32768)
        buffer = ctypes.create_unicode_buffer(size.value)
        if _kernel32.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size)):
            return buffer.value or None
        return None
    finally:
        _kernel32.CloseHandle(handle)


def list_processes(*, with_paths: bool = True) -> list[ProcessEntry]:
    """Снимок всех процессов."""
    if not IS_WINDOWS:
        return []
    snapshot = _kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snapshot == _INVALID_HANDLE or not snapshot:
        return []
    out: list[ProcessEntry] = []
    try:
        entry = _ProcessEntry32W()
        entry.dwSize = ctypes.sizeof(_ProcessEntry32W)
        ok = _kernel32.Process32FirstW(snapshot, ctypes.byref(entry))
        while ok:
            pid = int(entry.th32ProcessID)
            name = str(entry.szExeFile)
            out.append(
                ProcessEntry(
                    pid=pid,
                    name=name,
                    path=image_path(pid) if with_paths and pid > 4 else None,
                    parent_pid=int(entry.th32ParentProcessID),
                )
            )
            ok = _kernel32.Process32NextW(snapshot, ctypes.byref(entry))
    finally:
        _kernel32.CloseHandle(snapshot)
    return out


def terminate(pid: int) -> bool:
    """Снять процесс. Ложь означает «не хватило прав» — обычно так и есть,
    если процесс запущен системой, а программа работает без повышения."""
    if not IS_WINDOWS or pid <= 4:
        return False
    handle = _kernel32.OpenProcess(PROCESS_TERMINATE, False, pid)
    if not handle:
        return False
    try:
        return bool(_kernel32.TerminateProcess(handle, 1))
    finally:
        _kernel32.CloseHandle(handle)


def is_admin() -> bool:
    """Запущены ли мы с повышением. Без него правится только ветка пользователя."""
    if not IS_WINDOWS:
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def relaunch_as_admin(argv: list[str] | None = None) -> bool:
    """Перезапустить себя с запросом повышения прав.

    Отказ в окне контроля учётных записей — не ошибка программы, поэтому
    возвращаем признак, а не исключение: окно на него просто не закроется.
    """
    if not IS_WINDOWS:
        return False
    args = argv if argv is not None else sys.argv[1:]
    params = " ".join(f'"{a}"' for a in args)
    # У собранной программы sys.executable — это она сама, и добавлять к
    # строке запуска имя сценария нельзя: он туда не передаётся.
    if getattr(sys, "frozen", False):
        command = params
    else:
        command = f'"{sys.argv[0]}" {params}'.strip()
    try:
        rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, command, None, 1)
        return int(rc) > 32
    except (AttributeError, OSError):
        return False
