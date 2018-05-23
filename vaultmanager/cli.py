#!/usr/bin/env python
import os
import inspect
try:
    print("Not installed")
    from VaultManager import VaultManager
except ImportError:
    from vaultmanager.VaultManager import VaultManager


def main():
    VaultManager(os.path.split(inspect.getfile(VaultManager))[0])


if __name__ == "__main__":
    main()

