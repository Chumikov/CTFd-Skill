#!/usr/bin/env python3
"""examples/solve_flow.py — демонстрационный end-to-end сценарий.

Показывает типичный поток игрока: получить список задач -> открыть условие ->
скачать файлы -> подать флаг. Безопасен для повторного запуска: подача флага
выполняется только если задать --submit-id и --flag.

Запуск::

    export CTFD_HOST=https://ctf.example.com
    export CTFD_TOKEN=ctfd_xxxxxxxxxxxxxxxx
    python examples/solve_flow.py                       # только чтение
    python examples/solve_flow.py --submit-id 42 --flag 'flag{...}'
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

# Подключаем клиент из соседней папки scripts/.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
from ctfd_client import CTfdClient, CTfdError  # noqa: E402


def main() -> int:
    p = argparse.ArgumentParser(description="Демо-поток игрока CTFd.")
    p.add_argument("--host", default=os.environ.get("CTFD_HOST"))
    p.add_argument("--token", default=os.environ.get("CTFD_TOKEN"))
    p.add_argument("--show-id", type=int, help="показать детали конкретной задачи")
    p.add_argument("--submit-id", type=int, help="id задачи для подачи флага")
    p.add_argument("--flag", help="флаг для подачи (требует --submit-id)")
    args = p.parse_args()

    if not args.host or not args.token:
        sys.exit("Задайте CTFD_HOST и CTFD_TOKEN (env или --host/--token).")

    c = CTfdClient(args.host, token=args.token)

    # 1. Кто я и какое у меня место.
    me = c.me()
    print(f"[me] {me.get('name')} — место {me.get('place')}, баллов {me.get('score')}")

    # 2. Список задач.
    chals = c.list_challenges()
    print(f"[challenges] всего {len(chals)} задач")
    for ch in chals[:10]:
        solved = "✓" if ch.get("solved_by_me") else " "
        print(f"  [{solved}] #{ch['id']:>3} {ch['category']:<12} "
              f"{ch['value']:>4}  solves={ch.get('solves', 0):>3}  {ch['name']}")

    # 3. Детали одной задачи (по запросу).
    if args.show_id:
        d = c.get_challenge(args.show_id)
        print(f"\n[challenge {args.show_id}] {d.get('name')} "
              f"({d.get('category')}, {d.get('value')} баллов)")
        print(f"  connection_info: {d.get('connection_info')}")
        print(f"  files: {len(d.get('files', []))}")
        for f in d.get("files", []):
            print(f"    - {f}")
        print(f"  hints: {len(d.get('hints', []))}")

    # 4. Подача флага (только если явно попросили).
    if args.submit_id:
        if not args.flag:
            sys.exit("Для --submit-id нужен также --flag.")
        verdict = c.attempt(args.submit_id, args.flag)
        status = verdict.get("status")
        print(f"\n[attempt {args.submit_id}] status={status} :: {verdict.get('message')}")
        if status == "correct":
            print("  Флаг принят, баллы начислены.")
        elif status == "already_solved":
            print("  Уже решено ранее — повторной подачи не требуется.")

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except CTfdError as e:
        sys.exit(f"CTfdError: {e}")
