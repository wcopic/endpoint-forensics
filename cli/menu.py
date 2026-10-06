def show_menu():
    print("\n" + "=" * 50)
    print("              ENDPOINT FORENSICS")
    print("=" * 50)

    print("\n[1] Show process tree")
    print("[2] Investigate process")
    print("[0] Exit")

    return input("\nSelect an option: ").strip()


def display_process_details(details, ancestors):
    process = details["process"]
    parent = details["parent"]
    children = details["children"]

    print("\n" + "=" * 50)
    print("              PROCESS DETAILS")
    print("=" * 50)

    print(f"\nName:        {process.get('name', 'Unknown')}")
    print(f"PID:         {process.get('pid', 'Unknown')}")
    print(f"Parent PID:  {process.get('parent_pid', 'Unknown')}")
    print(f"Path:        {process.get('path', 'Unknown')}")
    print(f"User:        {process.get('username', 'Unknown')}")
    print(f"Created:     {process.get('create_time', 'Unknown')}")

    print(f"Observed:     {process.get('observed_at', 'Unknown')}")

    print(f"Command line: {process.get('command_line', 'Unknown')}")


    print("\nParent:")

    if parent:
        print(f"  {parent['name']} (PID: {parent['pid']})")
    else:
        print("  Not present in snapshot")

    print("\nAncestors:")

    if ancestors[2:]:
        for ancestor in ancestors[2:]:
            print(
                f"  ↑ {ancestor['name']} "
                f"(PID: {ancestor['pid']})"
            )
    else:
        print("  None")

    print("\nChildren:")

    if children:
        for child in children:
            print(
                f"  └── {child['name']} "
                f"(PID: {child['pid']})"
            )
    else:
        print("  None")
