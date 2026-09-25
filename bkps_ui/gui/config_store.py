#!/usr/bin/env python3
"""
config_store.py - Singleton that holds the active Config object.

All tabs obtain a reference via ConfigStore.instance() so they share
the same Config without passing it through every constructor.  The
ConfigStore wraps bkps_config.Config and delegates load/save to the
underlying bkps_config helpers (load_config, create_config).

Exports:
    ConfigStore  - the singleton wrapper class

Typical usage::

    store = ConfigStore()          # created once in main.py
    # … elsewhere …
    store = ConfigStore.instance() # retrieves the same object
    cfg   = store.cfg              # access the live Config
"""

import sys
import os

from PySide6.QtCore import QSettings

# Make bkps/ (parent) importable so bkps_config etc. can be found
_bkps = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _bkps not in sys.path:
    sys.path.insert(0, _bkps)

from bkps_config import Config, load_config, create_config  # noqa: E402


_SETTINGS_ORGANIZATION = "Intel"
_SETTINGS_APPLICATION = "BKPS-Studio"
_LAST_CONFIG_KEY = "session/last_config_file"


class ConfigStore:
    """Singleton holding the active Config.

    Only one ConfigStore exists at a time; the most recently constructed
    instance is stored in the class-level _instance attribute and returned
    by ConfigStore.instance().
    """

    _instance: "ConfigStore | None" = None

    def __init__(self):
        """Create the ConfigStore and initialise an empty Config.

        GUI starts without any project paths; the user fills them in
        via the Config tab.  This avoids errors when tabs read cfg
        attributes that might not exist on a freshly constructed Config.
        """
        self._cfg: Config = Config()
        # GUI starts with empty project paths; user sets these explicitly in Config tab.
        self._cfg.bkps_dir = ""
        self._cfg.quartus_keys_dir = ""
        self._cfg.cm_provisioning_dir = ""
        self._cfg.bkps_repo_dir = ""
        self._cfg.config_file = ""
        ConfigStore._instance = self

    @classmethod
    def instance(cls) -> "ConfigStore":
        """Return the shared ConfigStore, creating one if none exists yet.

        Returns:
            The singleton ConfigStore instance.
        """
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @property
    def cfg(self) -> Config:
        """The live Config object shared across all tabs."""
        return self._cfg

    def load(self, path: str) -> None:
        """Load config from *path* into the shared Config object.

        Args:
            path: Absolute or relative path to the .conf/.cfg file.

        Raises:
            Exception: Propagates any error raised by bkps_config.load_config.
        """
        path = os.path.abspath(os.path.expandvars(os.path.expanduser(path)))
        self._cfg.config_file = path
        load_config(self._cfg)
        self._remember_config_path(path)

    def save(self, path: str | None = None) -> None:
        """Write current config to *path* (defaults to cfg.config_file).

        Args:
            path: Destination file path.  If omitted the config is written
                  back to cfg.config_file (the last loaded path).

        Raises:
            Exception: Propagates any error raised by bkps_config.create_config.
        """
        target = path or self._cfg.config_file
        target = os.path.abspath(os.path.expandvars(os.path.expanduser(target)))
        self._cfg.config_file = target
        create_config(self._cfg)
        self._remember_config_path(target)

    def restore_last(self) -> str:
        """Load the last successfully loaded or saved config file.

        Only the config-file path is stored in the per-user GUI settings;
        project credentials remain in the operator-selected config file.  A
        missing or moved file is ignored so a new workstation still opens in
        the safe first-run state.

        Returns:
            The restored absolute path, or ``""`` when none is available.
        """
        try:
            settings = QSettings(_SETTINGS_ORGANIZATION, _SETTINGS_APPLICATION)
            path = str(settings.value(_LAST_CONFIG_KEY, "") or "").strip()
        except Exception:
            return ""

        if not path:
            return ""
        path = os.path.abspath(os.path.expandvars(os.path.expanduser(path)))
        if not os.path.isfile(path):
            return ""
        self.load(path)
        return path

    @staticmethod
    def _remember_config_path(path: str) -> None:
        """Persist an absolute config path after a successful load or save."""
        try:
            settings = QSettings(_SETTINGS_ORGANIZATION, _SETTINGS_APPLICATION)
            settings.setValue(_LAST_CONFIG_KEY, path)
            settings.sync()
        except Exception:
            # Session convenience must never make config load/save fail.
            pass

    def get(self) -> Config:
        """Alias for the cfg property; retained for backward compatibility."""
        return self._cfg
