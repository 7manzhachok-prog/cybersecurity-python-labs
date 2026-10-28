import argparse
import hashlib
import json
import logging
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path


@dataclass
class FileRecord:
    path: str
    sha256: str
    size: int
    modified_at: str


def _resolved(path: Path) -> Path:
    return path.expanduser().resolve()


def scan_directory(directory: Path, excluded_paths: set[Path]) -> dict[str, FileRecord]:
    root = _resolved(directory)
    if not root.is_dir():
        raise NotADirectoryError(f"Каталог не знайдено: {root}")

    records = {}
    for file_path in sorted(root.rglob("*")):
        if file_path.is_symlink() or not file_path.is_file():
            continue

        resolved_file = _resolved(file_path)
        if resolved_file in excluded_paths:
            continue

        digest = hashlib.sha256()
        with file_path.open("rb") as file_handle:
            for chunk in iter(lambda: file_handle.read(1024 * 1024), b""):
                digest.update(chunk)

        stat = file_path.stat()
        relative_path = file_path.relative_to(root).as_posix()
        records[relative_path] = FileRecord(
            path=relative_path,
            sha256=digest.hexdigest(),
            size=stat.st_size,
            modified_at=datetime.fromtimestamp(stat.st_mtime, UTC).isoformat(),
        )

    return records


def _excluded_paths(baseline_path: Path, log_path: Path) -> set[Path]:
    return {_resolved(baseline_path), _resolved(log_path)}


def generate_baseline(directory: Path, baseline_path: Path, log_path: Path) -> int:
    records = scan_directory(directory, _excluded_paths(baseline_path, log_path))
    payload = {
        "version": 1,
        "generated_at": datetime.now(UTC).isoformat(),
        "directory": str(_resolved(directory)),
        "files": [asdict(records[path]) for path in sorted(records)],
    }

    output_path = _resolved(baseline_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"[INFO] Baseline saved: {output_path}")
    print(f"Total monitored files: {len(records)}")
    return 0


def load_baseline(baseline_path: Path) -> dict[str, FileRecord]:
    payload = json.loads(_resolved(baseline_path).read_text(encoding="utf-8"))
    files = payload if isinstance(payload, list) else payload.get("files")
    if not isinstance(files, list):
        raise ValueError("Некоректний baseline: поле 'files' має бути списком")

    records = {}
    for item in files:
        record = FileRecord(
            path=item["path"],
            sha256=item["sha256"],
            size=item["size"],
            modified_at=item.get("modified_at", item.get("modified", "")),
        )
        if record.path in records:
            raise ValueError(f"Некоректний baseline: повторюється шлях {record.path}")
        records[record.path] = record
    return records


def check_integrity(directory: Path, baseline_path: Path, log_path: Path) -> int:
    baseline = load_baseline(baseline_path)
    current = scan_directory(directory, _excluded_paths(baseline_path, log_path))

    baseline_paths = set(baseline)
    current_paths = set(current)
    created_paths = sorted(current_paths - baseline_paths)
    deleted_paths = sorted(baseline_paths - current_paths)
    modified_paths = sorted(
        path for path in baseline_paths & current_paths
        if baseline[path].sha256 != current[path].sha256
    )
    unchanged_count = len(baseline_paths & current_paths) - len(modified_paths)

    print("\n=== File Integrity Inspection Summary ===")
    print(f"Total monitored files : {len(current)}")
    print(f"Unchanged files       : {unchanged_count}")
    print(f"Modified files        : {len(modified_paths)}")
    print(f"Created files         : {len(created_paths)}")
    print(f"Deleted files         : {len(deleted_paths)}")

    if not (modified_paths or created_paths or deleted_paths):
        print("\n[INFO] No integrity changes detected.")
        return 0

    print("\n=== Detected Anomalies ===")
    for path in modified_paths:
        print(f"[MODIFIED] {path}")
        print(f"  Expected SHA-256: {baseline[path].sha256}")
        print(f"  Actual SHA-256  : {current[path].sha256}")
    for path in created_paths:
        print(f"[CREATED]  {path} (size: {current[path].size} B)")
    for path in deleted_paths:
        print(f"[DELETED]  {path}")

    audit_path = _resolved(log_path)
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("fim.audit")
    logger.setLevel(logging.WARNING)
    handler = logging.FileHandler(audit_path, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    logger.addHandler(handler)
    try:
        for path in modified_paths:
            logger.warning("Modified file detected: %s", path)
        for path in created_paths:
            logger.warning("Created file detected: %s", path)
        for path in deleted_paths:
            logger.warning("Deleted file detected: %s", path)
    finally:
        logger.removeHandler(handler)
        handler.close()

    print(f"\n[WARNING] Security alerts detected. Check audit log at {audit_path}")
    return 1


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Монітор цілісності файлів і каталогів (FIM)")
    parser.add_argument("--dir", type=Path, required=True, help="Каталог для рекурсивного моніторингу")
    parser.add_argument("--baseline", type=Path, default=Path("data/baseline.json"), help="Шлях до JSON baseline")
    parser.add_argument("--mode", choices=("generate", "check"), required=True, help="Створити baseline або перевірити цілісність")
    parser.add_argument("--log-file", type=Path, default=Path("data/fim_audit.log"), help="Файл журналу попереджень")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if args.mode == "generate":
            return generate_baseline(args.dir, args.baseline, args.log_file)
        return check_integrity(args.dir, args.baseline, args.log_file)
    except (OSError, json.JSONDecodeError, TypeError, ValueError) as error:
        print(f"[ERROR] {error}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
