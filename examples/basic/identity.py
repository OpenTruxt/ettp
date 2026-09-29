"""Example ETTP bootstrap usage."""

import ettp


def main() -> None:
    """Print the package-level ETTP protocol constants."""
    print(ettp.PROTOCOL_NAME)
    print(ettp.PROTOCOL_VERSION)
    print(ettp.SCHEMA_VERSION)


if __name__ == "__main__":
    main()
