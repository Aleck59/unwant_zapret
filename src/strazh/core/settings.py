"""Настройки: какие механизмы включены, за какими папками следить, исключения.

Отдельно от каталога намеренно. Каталог отвечает на вопрос «что нежелательно»,
настройки — «как сильно давить». Обновление программы обновляет первое и не
трогает второе.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from strazh.core.matcher import Allowlist


@dataclass(slots=True)
class Mechanisms:
    """Переключатели способов блокировки.

    Разделены, потому что цена у них разная. Перехват запуска через реестр
    и наблюдатель за процессами безобидны и включены сразу. Правка hosts
    задевает всю сеть машины и по умолчанию выключена: одна общая запись
    способна отломить обновления там, где их не ждали.
    """

    ifeo: bool = True
    """Перехват запуска по имени файла через Image File Execution Options."""

    srp: bool = True
    """Политики ограниченного использования программ: маски путей и суммы."""

    disallow_run: bool = False
    """Запрет запуска из оболочки. Слабый слой, обходится переименованием."""

    process_watch: bool = True
    """Наблюдение за запуском процессов. Ловит переименованные файлы."""

    download_watch: bool = True
    """Наблюдение за папками загрузок: установщик задерживают до запуска."""

    firewall: bool = True
    """Правила брандмауэра на исходящие соединения найденных программ."""

    hosts: bool = False
    """Закрытие адресов через hosts. Выключено: задевает всю машину."""

    defender_pua: bool = True
    """Встроенная в Windows защита от нежелательных программ (PUA)."""

    neutralize_services: bool = True
    """Остановка и отключение служб и заданий уже установленных целей."""


@dataclass(slots=True)
class Settings:
    mechanisms: Mechanisms = field(default_factory=Mechanisms)

    watch_dirs: list[str] = field(default_factory=list)
    """Папки, где ждут установщики. Пусто — берутся стандартные: загрузки
    всех учётных записей, рабочий стол и временные папки."""

    quarantine: bool = True
    """Найденный установщик убирается в карантин, а не удаляется. Удаление —
    необратимо, а ошибиться правило может."""

    autostart: bool = True
    """Запускать наблюдателя вместе с системой."""

    notify: bool = True
    overrides: dict[str, dict[str, Any]] = field(default_factory=dict)
    """Правки к записям каталога: `{"mcafee": {"enabled": false}}`."""

    allow_names: list[str] = field(default_factory=list)
    allow_paths: list[str] = field(default_factory=list)
    allow_sha256: list[str] = field(default_factory=list)

    def allowlist(self) -> Allowlist:
        return Allowlist(
            names=set(self.allow_names),
            paths=list(self.allow_paths),
            sha256=set(self.allow_sha256),
        )

    def set_enabled(self, target_id: str, enabled: bool) -> None:
        self.overrides.setdefault(target_id, {})["enabled"] = enabled

    def to_json(self) -> dict[str, Any]:
        data = asdict(self)
        return data

    @staticmethod
    def from_json(raw: dict[str, Any]) -> Settings:
        settings = Settings()
        mech = raw.get("mechanisms")
        if isinstance(mech, dict):
            for name in Mechanisms.__annotations__:
                if name in mech:
                    setattr(settings.mechanisms, name, bool(mech[name]))
        for name in ("quarantine", "autostart", "notify"):
            if name in raw:
                setattr(settings, name, bool(raw[name]))
        for name in ("watch_dirs", "allow_names", "allow_paths", "allow_sha256"):
            value = raw.get(name)
            if isinstance(value, list):
                setattr(settings, name, [str(v) for v in value])
        overrides = raw.get("overrides")
        if isinstance(overrides, dict):
            settings.overrides = {
                str(k): dict(v) for k, v in overrides.items() if isinstance(v, dict)
            }
        return settings


def load_settings(path: Path) -> Settings:
    try:
        return Settings.from_json(json.loads(path.read_text(encoding="utf-8")))
    except (OSError, json.JSONDecodeError, TypeError):
        return Settings()


def save_settings(path: Path, settings: Settings) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(
        json.dumps(settings.to_json(), ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    tmp.replace(path)
