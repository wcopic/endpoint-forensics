import argparse

from acquisition.snapshot import capture_snapshot, load_snapshot
from analysis.process_tree import print_process_tree, get_process_details, get_process_ancestors
from cli.menu import show_menu, display_process_details


def main():
    parser = argparse.ArgumentParser(description="Collect or inspect local endpoint evidence.")
    options = parser.add_mutually_exclusive_group()
    options.add_argument("--deep-analysis", action="store_true",
                         help="Also collect Authenticode signatures and mapped file paths.")
    options.add_argument("--load", metavar="DIRECTORY", help="Load a previous evidence directory.")
    args = parser.parse_args()
    print("=" * 50)
    print("       ENDPOINT FORENSICS — CLI")
    print("=" * 50)
    try:
        snapshot = load_snapshot(args.load) if args.load else capture_snapshot(deep_analysis=args.deep_analysis)
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.exit(1, f"Acquisition/load failed: {error}\n")
    system = snapshot["system"]
    print(f"\nHostname: {system.get('hostname', 'Unknown')}")
    print(f"User: {system.get('username', 'Unknown')}")
    print(f"OS: {system.get('operating_system', 'Unknown')}")
    print(f"Processes found: {len(snapshot['processes'])}")
    print(f"Evidence: {snapshot['evidence_path']}")
    for warning in snapshot["metadata"].get("warnings", []):
        print(f"[!] {warning}")
    process_map, children = snapshot["process_map"], snapshot["children"]
    while True:
        try:
            option = show_menu()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting...")
            break
        if option == "1":
            visited = set()
            child_pids = {pid for pids in children.values() for pid in pids}
            roots = [pid for pid in process_map if pid not in child_pids]
            # Also display disconnected/cyclic legacy records without looping.
            for pid in roots + list(process_map):
                print_process_tree(pid, process_map, children, visited=visited)
        elif option == "2":
            pid_input = input("\nEnter PID: ").strip()
            if not pid_input.isdigit():
                print("\n[!] Invalid PID.")
                continue
            pid = int(pid_input)
            details = get_process_details(pid, process_map, children)
            if details is None:
                print(f"\n[!] Process with PID {pid} not found.")
                continue
            display_process_details(details, get_process_ancestors(pid, process_map))
        elif option == "0":
            break
        else:
            print("\n[!] Invalid option.")


if __name__ == "__main__":
    main()
