from src.aids import aids_main
from src.sids import sids_main


def print_banner() -> None:
    # Font : ANSI Shadow
    # Made at https://www.patorjk.com/software/taag/#p=display&h=0&v=0&f=ANSI%20Shadow&t=HYBRID%20NIDS
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
            # sids_main.main(handle_unknown_packets=True,funnel_packets=True)
            sids_main.main(
                handle_unknown_packets=True, funnel_packets=True, mode="Hybrid"
            )
        elif choice == "2":
            print("Initiating standalone Signature IDS...")
            sids_main.main(
                handle_unknown_packets=False, funnel_packets=False, mode="Signature"
            )
        elif choice == "3":
            print("Initiating standalone Anomaly IDS...")
            aids_main.main(funnel_packets=False, packets=None)
        elif choice == "4":
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please enter a number between 1 and 4.")


if __name__ == "__main__":
    main()
