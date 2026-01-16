"""Configuration management for Network Analytics Toolkit."""

import json
import os
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ScanConfig:
    """Scanning configuration."""

    default_ports: str = "1-1000"
    timeout: float = 2.0
    rate_limit: int = 100  # packets per second
    max_retries: int = 2


@dataclass
class CaptureConfig:
    """Traffic capture configuration."""

    default_count: int = 100
    default_timeout: int = 60
    snap_length: int = 65535
    buffer_size: int = 2097152  # 2MB


@dataclass
class TopologyConfig:
    """Topology visualization configuration."""

    default_layout: str = "spring"
    figure_size: tuple[int, int] = (12, 8)
    node_size: int = 500
    font_size: int = 8


@dataclass
class Config:
    """Main configuration for Network Analytics Toolkit."""

    results_dir: Path = field(default_factory=lambda: Path("./results"))
    scan: ScanConfig = field(default_factory=ScanConfig)
    capture: CaptureConfig = field(default_factory=CaptureConfig)
    topology: TopologyConfig = field(default_factory=TopologyConfig)
    verbose: bool = False
    fast_mode: bool = False

    def __post_init__(self) -> None:
        if isinstance(self.results_dir, str):
            self.results_dir = Path(self.results_dir)

    @classmethod
    def from_file(cls, path: Path) -> "Config":
        """Load configuration from JSON file."""
        if not path.exists():
            return cls()

        with open(path) as f:
            data = json.load(f)

        config = cls()
        if "results_dir" in data:
            config.results_dir = Path(data["results_dir"])
        if "verbose" in data:
            config.verbose = data["verbose"]
        if "fast_mode" in data:
            config.fast_mode = data["fast_mode"]

        if "scan" in data:
            for key, value in data["scan"].items():
                if hasattr(config.scan, key):
                    setattr(config.scan, key, value)

        if "capture" in data:
            for key, value in data["capture"].items():
                if hasattr(config.capture, key):
                    setattr(config.capture, key, value)

        if "topology" in data:
            for key, value in data["topology"].items():
                if hasattr(config.topology, key):
                    setattr(config.topology, key, value)

        return config

    def save(self, path: Path) -> None:
        """Save configuration to JSON file."""
        data = {
            "results_dir": str(self.results_dir),
            "verbose": self.verbose,
            "fast_mode": self.fast_mode,
            "scan": {
                "default_ports": self.scan.default_ports,
                "timeout": self.scan.timeout,
                "rate_limit": self.scan.rate_limit,
                "max_retries": self.scan.max_retries,
            },
            "capture": {
                "default_count": self.capture.default_count,
                "default_timeout": self.capture.default_timeout,
                "snap_length": self.capture.snap_length,
                "buffer_size": self.capture.buffer_size,
            },
            "topology": {
                "default_layout": self.topology.default_layout,
                "figure_size": list(self.topology.figure_size),
                "node_size": self.topology.node_size,
                "font_size": self.topology.font_size,
            },
        }
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            json.dump(data, f, indent=2)


_config: Config | None = None


def get_config() -> Config:
    """Get the global configuration instance."""
    global _config
    if _config is None:
        config_path = Path(os.environ.get("NETANALYTICS_CONFIG", ".netanalytics.json"))
        _config = Config.from_file(config_path)
    return _config


def set_config(config: Config) -> None:
    """Set the global configuration instance."""
    global _config
    _config = config
