"""`python -m strazh` — окно, `python -m strazh <команда>` — командная строка."""

from __future__ import annotations

import sys


def main() -> int:
    if len(sys.argv) > 1:
        from strazh.cli import main as cli_main

        return cli_main()
    from strazh.gui.app import main as gui_main

    return gui_main()


if __name__ == "__main__":
    raise SystemExit(main())
