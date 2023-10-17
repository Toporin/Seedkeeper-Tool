# -*- mode: python ; coding: utf-8 -*-

import os
import sys
import platform
# from package.build_win_verinfo import fill_version_info

# from uniblow import SUPPORTED_COINS, DEVICES_LIST
from seedkeeper.version import SEEDKEEPERTOOL_VERSION


current_path = os.path.dirname(os.path.abspath("seedkeeper.spec"))
sys.path.append(current_path)

ICON = "../seedkeeper/satochip.ico"
FILE_DESCRIPTION = "SeedKeeperTool application executable"
COMMENTS = "GUI application to use a Seedkeeper (seedkeeper.io)"


os_system = platform.system()
if os_system == "Windows":
    os_platform = "win"
elif os_system == "Linux":
    os_platform = "linux"
elif os_system == "Darwin":
    os_platform = "mac"
else:
    raise Exception("Unknown platform target")
plt_arch = platform.machine().lower()
BIN_PKG_NAME = f"SeedKeeper-{os_platform}-{plt_arch}-{SEEDKEEPERTOOL_VERSION}"

# additional_imports = [f"wallets.{coinpkg}wallet" for coinpkg in SUPPORTED_COINS]
# additional_imports += [f"devices.{device}" for device in DEVICES_LIST]

# if os_platform == "mac":
#     additional_imports.append("certifi")

pkgs_remove = [
    "sqlite3",
    "tcl85",
    "tk85",
    "_sqlite3",
    "_tkinter",
    "libopenblas",
    "libdgamln",
    "libdbus",
]

datai = [
    ("../seedkeeper/*.png", "seedkeeper/"),
    ("../seedkeeper/wordlist/*.txt", "seedkeeper/wordlist"),
    ("../seedkeeper/help/*.txt", "seedkeeper/help/"),
]

a = Analysis(
    ["../seedkeeper/seedkeeper.py"],
    pathex=[current_path],
    binaries=[],
    datas=datai,
    hiddenimports=additional_imports,
    hookspath=[],
    runtime_hooks=[],
    excludes=[
        "_gtkagg",
        "_tkagg",
        "curses",
        "pywin.debugger",
        "pywin.debugger.dbgcon",
        "pywin.dialogs",
        "tcl",
        "Tkconstants",
        "Tkinter",
        "libopenblas",
        "libdgamln",
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=None,
    noarchive=False,
)

for pkg in pkgs_remove:
    a.binaries = [x for x in a.binaries if not x[0].startswith(pkg)]

pyz = PYZ(a.pure, a.zipped_data, cipher=None)

if os_platform == "win":
    fill_version_info(BIN_PKG_NAME, SEEDKEEPERTOOL_VERSION, FILE_DESCRIPTION, COMMENTS)
    version_info_file = "version_info"
else:
    version_info_file = None

exe_options = [a.scripts]

if os_platform == "mac":
    bins_apart = True
    BIN_PKG_NAME = "seedkeepertool"
else:
    bins_apart = False
    exe_options += [a.binaries, a.zipfiles, a.datas]

exe = EXE(
    pyz,
    *exe_options,
    [],
    exclude_binaries=bins_apart,
    name=BIN_PKG_NAME,
    icon=ICON,
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    version=version_info_file,
)

if os_platform == "mac":
    coll = COLLECT(
        exe,
        a.binaries,
        a.zipfiles,
        a.datas,
        strip=False,
        upx=True,
        upx_exclude=[],
        name="seedkeeper-bundle",
    )

    app = BUNDLE(
        coll,
        name="seedkeeper.app",
        icon=ICON,
        bundle_identifier="io.seedkeeper.tool",
        version=SEEDKEEPERTOOL_VERSION,
        info_plist={
            "NSPrincipalClass": "NSApplication",
            "NSHighResolutionCapable": True,
            "NSAppleScriptEnabled": False,
            "CFBundleIdentifier": "io.seedkeeper.tool",
            "CFBundleName": "seedkeeper",
            "CFBundleDisplayName": "seedkeeper",
            "CFBundleVersion": SEEDKEEPERTOOL_VERSION,
            "CFBundleShortVersionString": SEEDKEEPERTOOL_VERSION,
            "LSEnvironment": {
                "LANG": "en_US.UTF-8",
                "LC_CTYPE": "en_US.UTF-8",
            },
            "NSHumanReadableCopyright": "Copyright (C) 2021-2023 Satochip",
        },
    )
