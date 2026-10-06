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
    metadata = {
        "path": str(file_path), "name": file_path.name,
        "size": None, "created_time": None, "modified_time": None,
        "accessed_time": None, "sha256": None,
        "collection_status": "collected", "error": None,
    }
    try:
        stat = file_path.stat()
        metadata.update(
            size=stat.st_size,
            created_time=getattr(stat, "st_birthtime", stat.st_ctime),
            modified_time=stat.st_mtime, accessed_time=stat.st_atime,
            sha256=calculate_sha256(file_path),
        )
        if metadata["sha256"] is None:
            metadata.update(collection_status="partial", error="File hash could not be read.")
    except PermissionError as error:
        metadata.update(collection_status="access_denied", error=str(error))
    except FileNotFoundError as error:
        metadata.update(collection_status="file_missing", error=str(error))
    except OSError as error:
        metadata.update(collection_status="error", error=str(error))
    return metadata


def collect_executables(processes):
    executables = {}
    for process in processes:
        path = process.get("path")
        if not path:
            continue
        normalized_path = str(Path(path)).lower()
        if normalized_path not in executables:
            executables[normalized_path] = collect_file_metadata(path)
    return list(executables.values())
