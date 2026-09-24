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

    print(f"\nName:        {process['name']}")
    print(f"PID:         {process['pid']}")
    print(f"Parent PID:  {process['parent_pid']}")
    print(f"Path:        {process['path']}")
    print(f"User:        {process['username']}")
    print(f"Created:     {process['create_time']}")

    print(f"Observed:     {process['observed_at']}")  

    print(f"Command line: {process['command_line']}")
    

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