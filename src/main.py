from src.aids import aids_main
from src.sids import sids_main


def print_banner() -> None:
    banner = """
    ██╗  ██╗██╗   ██╗██████╗ ██████╗ ██╗██████╗     ███╗   ██╗██╗██████╗ ███████╗
    ██║  ██║╚██╗ ██╔╝██╔══██╗██╔══██╗██║██╔══██╗    ████╗  ██║██║██╔══██╗██╔════╝
    ███████║ ╚████╔╝ ██████╔╝██████╔╝██║██║  ██║    ██╔██╗ ██║██║██║  ██║███████╗
    ██╔══██║  ╚██╔╝  ██╔══██╗██╔══██╗██║██║  ██║    ██║╚██╗██║██║██║  ██║╚════██║
    ██║  ██║   ██║   ██████╔╝██║  ██║██║██████╔╝    ██║ ╚████║██║██████╔╝███████║
    ╚═╝  ╚═╝   ╚═╝   ╚═════╝ ╚═╝  ╚═╝╚═╝╚═════╝     ╚═╝  ╚═══╝╚═╝╚═════╝ ╚══════╝
    """
    print(banner)


def main():
    print_banner()
    while True:
        print("\nSelect an option:")
        print("1. Initiate Hybrid System (SIDS and AIDS)")
        print("2. Initiate SIDS")
        print("3. Initiate AIDS")
        print("4. Exit")
        choice = input("Enter your choice (1-4): ")

        if choice == "1":
            print("Initiating Hybrid System...")
            sids_main.main()
        elif choice == "2":
            print("Initiating SIDS...")
            sids_main.main()
        elif choice == "3":
            print("Initiating AIDS...")
            aids_main.main()
        elif choice == "4":
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please enter a number between 1 and 4.")


if __name__ == "__main__":
    main()
