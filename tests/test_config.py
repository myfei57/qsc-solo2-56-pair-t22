"""配置解析与校验。"""

from __future__ import annotations

import json

import pytest

from psdline.config import (
    ConsoleSection,
    PlatformConfig,
    config_from_mapping,
    config_to_mapping,
    default_config,
    load_config,
    with_storage_root,
)
from psdline.errors import ConfigError


def test_default_config_is_valid():
    config = default_config()
    assert config.name == "psdline"
    assert config.namespace.line == "L1"
    assert config.console.port == 8080


def test_config_roundtrip_mapping():
    config = default_config()
    restored = config_from_mapping(config_to_mapping(config))
    assert restored == config


def test_config_rejects_bad_values():
    payload = config_to_mapping(default_config())
    payload["station"]["groups_per_station"] = 0
    with pytest.raises(ConfigError):
        config_from_mapping(payload)
    payload = config_to_mapping(default_config())
    payload["signal"]["sequence_modulus"] = 1000
    with pytest.raises(ConfigError):
        config_from_mapping(payload)
    payload = config_to_mapping(default_config())
    payload["console"]["port"] = 0
    with pytest.raises(ConfigError):
        config_from_mapping(payload)


def test_config_rejects_missing_namespace_stations():
    payload = config_to_mapping(default_config())
    payload["namespace"]["stations"] = []
    with pytest.raises(ConfigError):
        config_from_mapping(payload)
    assert PlatformConfig().validate() is not None


def test_load_config_from_file(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(json.dumps(config_to_mapping(default_config())), encoding="utf-8")
    assert load_config(str(path)).name == "psdline"
    with pytest.raises(ConfigError):
        load_config(str(tmp_path / "missing.json"))


def test_with_storage_root_replaces_directory():
    config = with_storage_root(default_config(), "var/other")
    assert config.storage_root == "var/other"
    assert config.name == "psdline"
    with pytest.raises(ConfigError):
        with_storage_root(default_config(), "")


def test_console_section_defaults():
    section = ConsoleSection()
    assert (section.host, section.port) == ("127.0.0.1", 8080)


def test_auth_section_defaults_and_roundtrip():
    config = default_config()
    assert config.auth.enabled is True
    assert config.auth.session_idle_s <= config.auth.session_absolute_s
    assert {principal.role for principal in config.auth.principals} == {
        "viewer",
        "operator",
        "dispatcher",
        "supervisor",
    }
    restored = config_from_mapping(config_to_mapping(config))
    assert restored.auth.principals == config.auth.principals


def test_auth_section_rejects_bad_principals():
    payload = config_to_mapping(default_config())
    payload["auth"]["principals"][1]["stations"] = []
    with pytest.raises(ConfigError):
        config_from_mapping(payload)
    payload = config_to_mapping(default_config())
    payload["auth"]["principals"][0]["role"] = "root"
    with pytest.raises(ConfigError):
        config_from_mapping(payload)
    payload = config_to_mapping(default_config())
    payload["auth"]["ticket_ttl_s"] = 0
    with pytest.raises(ConfigError):
        config_from_mapping(payload)


def test_auth_section_absent_in_old_config_uses_defaults():
    """旧版本配置文件没有 auth 段时仍可加载，行为向后兼容。"""

    payload = config_to_mapping(default_config())
    payload.pop("auth")
    config = config_from_mapping(payload)
    assert config.auth.principals == default_config().auth.principals
