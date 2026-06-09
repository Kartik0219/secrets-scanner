"""secrets-scanner — detect hardcoded credentials and high-entropy strings."""

from .scanner import scan_directory, scan_file, scan_git_history
from .models import Finding

__all__ = ["scan_directory", "scan_file", "scan_git_history", "Finding"]
