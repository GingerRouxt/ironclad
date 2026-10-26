#!/usr/bin/env python3
"""Create qs import mapping outside the plugin; never edit installed shell sources."""
from pathlib import Path
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix='ironclad-qml-imports-') as directory:
    (Path(directory)/'qs').symlink_to('/usr/share/omarchy/shell',target_is_directory=True)
    result=subprocess.run(['/usr/lib/qt6/bin/qmllint','-I',directory,'-I','/usr/lib/qt6/qml',str(ROOT/'BarWidget.qml'),str(ROOT/'Panel.qml'),str(ROOT/'ui0237/Dashboard.qml'),str(ROOT/'ui0237/Workspace.qml'),str(ROOT/'ui0237/Protection.qml'),str(ROOT/'ui0237/Monitoring.qml'),str(ROOT/'ui0237/AutomaticMalware.qml'),str(ROOT/'ui0237/Overview.qml'),str(ROOT/'ui0237/ControlButton.qml'),str(ROOT/'ui0237/BodyText.qml'),str(ROOT/'ui0237/NavIcon.qml')],check=False)
    raise SystemExit(result.returncode)
