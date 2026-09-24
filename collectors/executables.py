import hashlib
from pathlib import Path


def calculate_sha256(path, chunk_size=1024 * 1024):
    sha256 = hashlib.sha256()

    try:
        with open(path, "rb") as file:
            while chunk := file.read(chunk_size):
                sha256.update(chunk)

        return sha256.hexdigest()

    except (FileNotFoundError, PermissionError, OSError):
        return None


def collect_file_metadata(path):
    if not path:
        return None

    file_path = Path(path)

    try:
        stat = file_path.stat()

        return {
            "path": str(file_path),
            "name": file_path.name,
            "size": stat.st_size,
            "created_time": stat.st_ctime,
            "modified_time": stat.st_mtime,
            "accessed_time": stat.st_atime,
            "sha256": calculate_sha256(file_path),
        }

    except (FileNotFoundError, PermissionError, OSError):
        return None

def collect_executables(processes):
    executables = {}

    for process in processes:
        path = process.get("path")

        if not path:
            continue

        normalized_path = str(Path(path)).lower()

        if normalized_path in executables:
            continue

        metadata = collect_file_metadata(path)

        if metadata:
            executables[normalized_path] = metadata

    return list(executables.values())