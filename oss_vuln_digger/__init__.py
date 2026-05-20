import importlib
import sys
from pathlib import Path
from pkgutil import extend_path

from oss_vuln_lab import __version__


_ALIASES = (
    "automation",
    "cli",
    "config",
    "corpus",
    "dashboard",
    "impact",
    "intelligence",
    "loader",
    "models",
    "pipeline",
    "registry",
    "reporting",
    "safety",
    "storage",
    "plugins",
    "plugins.base",
    "plugins.llm",
    "plugins.project_adapters",
    "plugins.validators",
    "plugins.vuln_families",
)


__path__ = extend_path(__path__, __name__)
SRC_PACKAGE = Path(__file__).resolve().parent.parent / "src" / "oss_vuln_lab"
if SRC_PACKAGE.exists():
    __path__.append(str(SRC_PACKAGE))

for alias in _ALIASES:
    module = importlib.import_module(f"oss_vuln_lab.{alias}")
    sys.modules[f"{__name__}.{alias}"] = module
    if "." not in alias:
        setattr(sys.modules[__name__], alias, module)

__all__ = ["__version__"]
