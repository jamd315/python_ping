import sys

from Pinger import ping


if __name__ == "__main__":
    if len(sys.argv) > 1:
        print(f"Pinged {sys.argv[1]} in {ping(sys.argv[1])}s")
    else:
        print(f"Pinged 1.1.1.1 in {ping('1.1.1.1')}s")
