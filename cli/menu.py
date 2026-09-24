def show_menu():
    print("\n" + "=" * 50)
    print("              ENDPOINT FORENSICS")
    print("=" * 50)

    print("\n[1] Show process tree")
    print("[2] Investigate process")
    print("[0] Exit")

    return input("\nSelect an option: ").strip()


def display_process_details(details):
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

    print("\nParent:")

    if parent:
        print(f"  {parent['name']} (PID: {parent['pid']})")
    else:
        print("  Not present in snapshot")

    print("\nChildren:")

    if children:
        for child in children:
            print(f"  └── {child['name']} (PID: {child['pid']})")
    else:
        print("  None")