"""Keep standalone clients free of service, desktop, and clipboard backends."""
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FORBIDDEN = {
    "arboard", "argon2", "aws-lc-rs", "iced", "iced_winit", "reqwest", "rfd",
    "tokio", "zbus", "zxcvbn", "password_manager",
}


def main():
    for package in ("pm-contracts", "pm-client"):
        output = subprocess.check_output(
            ["cargo", "tree", "--locked", "-p", package, "--no-default-features",
             "--edges", "normal,build", "--prefix", "none", "--format", "{p}"],
            cwd=ROOT, text=True,
        )
        names = {line.split()[0] for line in output.splitlines() if line.strip()}
        forbidden = names & FORBIDDEN
        if forbidden:
            raise SystemExit(f"{package} pulls in forbidden dependencies: {sorted(forbidden)}")
        print(f"{package}: dependency boundary passed")


if __name__ == "__main__":
    main()
