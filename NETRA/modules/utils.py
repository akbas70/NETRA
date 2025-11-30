class C:
    """ANSI color codes for terminal output."""
    END = "\033[0m"
    R = "\033[31m"   # RED
    G = "\033[32m"   # GREEN
    Y = "\033[33m"   # YELLOW
    B = "\033[34m"   # BLUE
    M = "\033[35m"   # MAGENTA
    C = "\033[36m"   # CYAN
    W = "\033[37m"   # WHITE

def log(msg, color=C.END):
    """Print a colored log message."""
    print(f"{color}{msg}{C.END}")
