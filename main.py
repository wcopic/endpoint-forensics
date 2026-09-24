import json
from datetime import datetime
from pathlib import Path

from collectors.system import collect_system_info
from collectors.processes import collect_processes

from analysis.process_tree import (
    build_process_tree,
    print_process_tree,
    get_process_details
)

from cli.menu import (
    show_menu,
    display_process_details
)


def create_evidence_directory():
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    path = Path("evidence") / timestamp
    path.mkdir(parents=True, exist_ok=True)

    return path


def main():
    print("=" * 50)
    print("       ENDPOINT FORENSICS v0.0.1")
    print("=" * 50)

    evidence_path = create_evidence_directory()

    print("\n[+] Collecting system information...")
    system_info = collect_system_info()

    print("[+] Collecting running processes...")
    processes = collect_processes()

    process_map, children = build_process_tree(processes)

    # Save system information
    with open(
        evidence_path / "system.json",
        "w",
        encoding="utf-8"
    ) as file:
        json.dump(system_info, file, indent=4)

    # Save process information
    with open(
        evidence_path / "processes.json",
        "w",
        encoding="utf-8"
    ) as file:
        json.dump(processes, file, indent=4)

    print("\n" + "=" * 50)
    print("COLLECTION COMPLETE")
    print("=" * 50)

    print(f"\nHostname: {system_info['hostname']}")
    print(f"User: {system_info['username']}")
    print(f"OS: {system_info['operating_system']}")
    print(f"CPU cores: {system_info['cpu_count']}")
    print(f"RAM: {system_info['memory_gb']} GB")
    print(f"Processes found: {len(processes)}")

    root_processes = [
        process["pid"]
        for process in processes
        if process["parent_pid"] not in process_map
    ]

    print("\n[+] Evidence saved to:")
    print(f"    {evidence_path}")

    while True:
        option = show_menu()

        if option == "1":
            print("\n[+] Process tree:\n")

            for pid in root_processes:
                print_process_tree(
                    pid,
                    process_map,
                    children
                )

        elif option == "2":
            pid_input = input("\nEnter PID: ").strip()

            if not pid_input.isdigit():
                print("\n[!] Invalid PID.")
                continue

            pid = int(pid_input)

            details = get_process_details(
                pid,
                process_map,
                children
            )

            if not details:
                print(
                    f"\n[!] Process with PID {pid} "
                    "not found."
                )
                continue

            display_process_details(details)

        elif option == "0":
            print("\nExiting...")
            break

        else:
            print("\n[!] Invalid option.")


if __name__ == "__main__":
    main()