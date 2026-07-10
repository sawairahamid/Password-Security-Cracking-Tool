import tkinter as tk
from gui import PasswordToolGUI


def main():
    """
    Application entry point.
    Initializes the GUI and handles startup-level errors safely.
    """
    try:
        root = tk.Tk()
        root.title("Password Analyzer and Cracking Tool")

        # Minimum window size for consistent UI
        WINDOW_WIDTH = 900
        WINDOW_HEIGHT = 600
        root.minsize(WINDOW_WIDTH, WINDOW_HEIGHT)

        # Center window on screen
        root.update_idletasks()
        screen_width = root.winfo_screenwidth()
        screen_height = root.winfo_screenheight()

        x = (screen_width // 2) - (WINDOW_WIDTH // 2)
        y = (screen_height // 2) - (WINDOW_HEIGHT // 2)

        root.geometry(f"{WINDOW_WIDTH}x{WINDOW_HEIGHT}+{x}+{y}")

        # Initialize GUI
        PasswordToolGUI(root)

        # Start event loop
        root.mainloop()

    except Exception as error:
        # Startup errors should be visible but not crash silently
        print("[ERROR] Application failed to start")
        print(f"Reason: {error}")


if __name__ == "__main__":
    main()
