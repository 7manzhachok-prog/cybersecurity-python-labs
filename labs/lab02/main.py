"""Точка входу ЛР №2: команди demo та analyze."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from labs.lab02 import task2
from labs.lab02.task1 import run_demo


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m labs.lab02.main")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("demo", help="демонстрація ООП-моделі (Завдання 1)")

    analyze = sub.add_parser("analyze", help="FIM: контроль цілісності (Варіант 2)")
    task2.add_arguments(analyze)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command is None:  # запуск кнопкою без аргументів: demo + analyze
        run_demo()
        print()
        return main(["analyze"])
    if args.command == "demo":
        run_demo()
        return 0
    return task2.run(args.mode, args.dir, args.baseline, args.log_file)


if __name__ == "__main__":
    raise SystemExit(main())
