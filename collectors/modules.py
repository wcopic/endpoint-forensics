from pathlib import Path

import psutil


def collect_loaded_modules(processes):

    modules_by_pid = {}


    for process in processes:

        pid = process.get("pid")

        if pid is None:
            continue


        try:

            live_process = psutil.Process(
                pid
            )

            modules = []

            seen_paths = set()


            for mapping in live_process.memory_maps():

                path = getattr(
                    mapping,
                    "path",
                    None
                )

                if not path:
                    continue


                normalized_path = (
                    path.lower()
                )


                if normalized_path in seen_paths:
                    continue


                seen_paths.add(
                    normalized_path
                )


                modules.append({
                    "name":
                        Path(path).name,

                    "path":
                        path
                })


            modules_by_pid[pid] = (
                modules
            )


        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied,
            psutil.ZombieProcess
        ):

            modules_by_pid[pid] = []


    return modules_by_pid