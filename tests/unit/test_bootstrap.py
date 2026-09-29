def test_package_imports() -> None:
    import ettp

    assert ettp.PROTOCOL_NAME == "ettp"


def test_protocol_version_exists() -> None:
    import ettp

    assert ettp.PROTOCOL_VERSION == "0.1"


def test_schema_version_exists() -> None:
    import ettp

    assert ettp.SCHEMA_VERSION == "v1"
