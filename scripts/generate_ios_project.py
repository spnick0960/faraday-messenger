#!/usr/bin/env python3
"""Generate Faraday.xcodeproj and a simple app icon."""
from __future__ import annotations

import hashlib
import struct
import zlib
from pathlib import Path

ROOT = Path("/workspace/ios/Faraday")
APP = ROOT / "Faraday"
PROJ = ROOT / "Faraday.xcodeproj"

SWIFT = [
    "FaradayApp.swift",
    "AppModel.swift",
    "Theme/Theme.swift",
    "Onboarding/WelcomeView.swift",
    "Onboarding/RecoveryPhraseView.swift",
    "Chats/InboxView.swift",
    "Chats/ThreadView.swift",
    "Contacts/MyInviteView.swift",
    "Contacts/AddContactView.swift",
    "Settings/SettingsView.swift",
    "Settings/ThreatModelView.swift",
    "Crypto/HKDF.swift",
    "Crypto/BIP39.swift",
    "Crypto/IdentityKeys.swift",
    "Crypto/X3DH.swift",
    "Crypto/DoubleRatchet.swift",
    "Crypto/Seal.swift",
    "Crypto/Invite.swift",
    "Crypto/DeviceCrypto.swift",
    "Network/RelayClient.swift",
    "Storage/KeychainStore.swift",
    "Storage/LocalStore.swift",
    "Models/Models.swift",
]

RESOURCES = [
    "Resources/bip39-english.txt",
    "Resources/PrivacyInfo.xcprivacy",
]


def uid(name: str) -> str:
    return hashlib.sha1(name.encode()).hexdigest()[:24].upper()


def png(w: int, h: int, rgba: bytes) -> bytes:
    def chunk(tag: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)

    raw = b""
    stride = w * 4
    for y in range(h):
        raw += b"\x00" + rgba[y * stride : (y + 1) * stride]
    return b"".join(
        [
            b"\x89PNG\r\n\x1a\n",
            chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 6, 0, 0, 0)),
            chunk(b"IDAT", zlib.compress(raw, 9)),
            chunk(b"IEND", b""),
        ]
    )


def make_icon(path: Path, size: int = 1024) -> None:
    rgba = bytearray()
    cx = cy = size / 2
    for y in range(size):
        for x in range(size):
            dx, dy = x - cx, y - cy
            r2 = dx * dx + dy * dy
            # dark field
            r, g, b = 12, 14, 18
            # brass ring (faraday cage)
            outer, inner = (size * 0.38) ** 2, (size * 0.30) ** 2
            if inner < r2 < outer:
                r, g, b = 196, 165, 116
            # vertical bars
            if abs(dx) < size * 0.018 and abs(dy) < size * 0.28:
                r, g, b = 196, 165, 116
            if abs(dx) < size * 0.14 and abs(dy) < size * 0.018:
                r, g, b = 196, 165, 116
            # lock body
            if abs(dx) < size * 0.09 and size * 0.02 < dy < size * 0.18:
                r, g, b = 232, 230, 225
            # lock shackle
            sh = (dx * dx) / (size * 0.07) ** 2 + ((dy + size * 0.02) ** 2) / (size * 0.09) ** 2
            if 0.55 < sh < 0.95 and dy < size * 0.03:
                r, g, b = 232, 230, 225
            rgba.extend((r, g, b, 255))
    path.write_bytes(png(size, size, bytes(rgba)))


def write_assets() -> None:
    assets = APP / "Assets.xcassets"
    (assets / "AppIcon.appiconset").mkdir(parents=True, exist_ok=True)
    (assets / "AccentColor.colorset").mkdir(parents=True, exist_ok=True)
    (assets / "LaunchBackground.colorset").mkdir(parents=True, exist_ok=True)
    make_icon(assets / "AppIcon.appiconset" / "AppIcon.png")
    (assets / "Contents.json").write_text(
        '{"info":{"author":"xcode","version":1}}\n'
    )
    (assets / "AppIcon.appiconset" / "Contents.json").write_text(
        """{
  "images" : [
    { "filename" : "AppIcon.png", "idiom" : "universal", "platform" : "ios", "size" : "1024x1024" }
  ],
  "info" : { "author" : "xcode", "version" : 1 }
}
"""
    )
    (assets / "AccentColor.colorset" / "Contents.json").write_text(
        """{
  "colors" : [{
    "color" : { "color-space" : "srgb",
      "components" : { "alpha" : "1.000", "red" : "0.769", "green" : "0.647", "blue" : "0.455" }
    },
    "idiom" : "universal"
  }],
  "info" : { "author" : "xcode", "version" : 1 }
}
"""
    )
    (assets / "LaunchBackground.colorset" / "Contents.json").write_text(
        """{
  "colors" : [{
    "color" : { "color-space" : "srgb",
      "components" : { "alpha" : "1.000", "red" : "0.047", "green" : "0.055", "blue" : "0.071" }
    },
    "idiom" : "universal"
  }],
  "info" : { "author" : "xcode", "version" : 1 }
}
"""
    )


def pbxproj() -> str:
    project = uid("project")
    target = uid("target")
    sources_phase = uid("sources")
    resources_phase = uid("resources")
    frameworks_phase = uid("frameworks")
    main_group = uid("maingroup")
    products = uid("products")
    faraday_group = uid("faradaygroup")
    product_ref = uid("productref")
    config_list_proj = uid("cfglproj")
    config_list_tgt = uid("cfgltgt")
    debug_proj = uid("dbgproj")
    release_proj = uid("relproj")
    debug_tgt = uid("dbgtgt")
    release_tgt = uid("reltgt")

    file_ids = {path: uid("file:" + path) for path in SWIFT + RESOURCES + ["Assets.xcassets", "Info.plist"]}
    build_ids = {path: uid("build:" + path) for path in SWIFT + RESOURCES + ["Assets.xcassets"]}

    groups: dict[str, list[str]] = {}
    for path in SWIFT + RESOURCES:
        parent = str(Path(path).parent)
        if parent == ".":
            parent = ""
        groups.setdefault(parent, []).append(path)
    group_ids = {name: uid("grp:" + name) for name in groups if name}

    def file_entry(path: str) -> str:
        name = Path(path).name
        ext = Path(path).suffix
        ftype = {
            ".swift": "sourcecode.swift",
            ".txt": "text",
            ".xcprivacy": "text.xml",
            ".plist": "text.plist.xml",
        }.get(ext, "text")
        return f'\t\t{file_ids[path]} /* {name} */ = {{isa = PBXFileReference; lastKnownFileType = {ftype}; path = {name}; sourceTree = "<group>"; }};'

    objects: list[str] = []
    objects.append(
        f'\t\t{product_ref} /* Faraday.app */ = {{isa = PBXFileReference; explicitFileType = wrapper.application; includeInIndex = 0; path = Faraday.app; sourceTree = BUILT_PRODUCTS_DIR; }};'
    )
    objects.append(
        f'\t\t{file_ids["Assets.xcassets"]} /* Assets.xcassets */ = {{isa = PBXFileReference; lastKnownFileType = folder.assetcatalog; path = Assets.xcassets; sourceTree = "<group>"; }};'
    )
    objects.append(
        f'\t\t{file_ids["Info.plist"]} /* Info.plist */ = {{isa = PBXFileReference; lastKnownFileType = text.plist.xml; path = Info.plist; sourceTree = "<group>"; }};'
    )
    for path in SWIFT + RESOURCES:
        objects.append(file_entry(path))

    for path in SWIFT:
        name = Path(path).name
        objects.append(
            f'\t\t{build_ids[path]} /* {name} in Sources */ = {{isa = PBXBuildFile; fileRef = {file_ids[path]} /* {name} */; }};'
        )
    for path in RESOURCES + ["Assets.xcassets"]:
        name = Path(path).name
        objects.append(
            f'\t\t{build_ids[path]} /* {name} in Resources */ = {{isa = PBXBuildFile; fileRef = {file_ids[path]} /* {name} */; }};'
        )

    def group_block(gid: str, name: str, children: list[str], paths: list[str] | None = None) -> str:
        lines = [f"\t\t{gid} /* {name} */ = {{", "\t\t\tisa = PBXGroup;", "\t\t\tchildren = ("]
        for c in children:
            lines.append(f"\t\t\t\t{c},")
        lines.append("\t\t\t);")
        if name not in ("", "Products"):
            lines.append(f"\t\t\tpath = {name};")
        lines.append('\t\t\tsourceTree = "<group>";')
        lines.append("\t\t};")
        return "\n".join(lines)

    # Nested groups
    subgroup_children: dict[str, list[str]] = {"": []}
    for folder, paths in groups.items():
        if folder:
            subgroup_children.setdefault(folder, [])
            for p in paths:
                subgroup_children[folder].append(f"{file_ids[p]} /* {Path(p).name} */")
        else:
            for p in paths:
                subgroup_children[""].append(f"{file_ids[p]} /* {Path(p).name} */")

    # top-level Faraday group children: loose files + subgroup ids + assets + plist
    faraday_children = list(subgroup_children.get("", []))
    for folder, gid in sorted(group_ids.items()):
        faraday_children.append(f"{gid} /* {folder} */")
    faraday_children.append(f'{file_ids["Assets.xcassets"]} /* Assets.xcassets */')
    faraday_children.append(f'{file_ids["Info.plist"]} /* Info.plist */')

    objects.append(group_block(main_group, "", [
        f"{faraday_group} /* Faraday */",
        f"{products} /* Products */",
    ]))
    objects.append(group_block(products, "Products", [f"{product_ref} /* Faraday.app */"]))
    objects.append(group_block(faraday_group, "Faraday", faraday_children))
    for folder, gid in group_ids.items():
        objects.append(group_block(gid, folder, subgroup_children[folder]))

    source_files = "\n".join(f"\t\t\t\t{build_ids[p]} /* {Path(p).name} in Sources */," for p in SWIFT)
    resource_files = "\n".join(
        f"\t\t\t\t{build_ids[p]} /* {Path(p).name} in Resources */," for p in RESOURCES + ["Assets.xcassets"]
    )

    objects.append(
        f"""\t\t{target} /* Faraday */ = {{
			isa = PBXNativeTarget;
			buildConfigurationList = {config_list_tgt} /* Build configuration list for PBXNativeTarget "Faraday" */;
			buildPhases = (
				{sources_phase} /* Sources */,
				{frameworks_phase} /* Frameworks */,
				{resources_phase} /* Resources */,
			);
			buildRules = (
			);
			dependencies = (
			);
			name = Faraday;
			productName = Faraday;
			productReference = {product_ref} /* Faraday.app */;
			productType = "com.apple.product-type.application";
		}};"""
    )
    objects.append(
        f"""\t\t{project} /* Project object */ = {{
			isa = PBXProject;
			attributes = {{
				BuildIndependentTargetsInParallel = 1;
				LastSwiftUpdateCheck = 1500;
				LastUpgradeCheck = 1500;
				TargetAttributes = {{
					{target} = {{
						CreatedOnToolsVersion = 15.0;
					}};
				}};
			}};
			buildConfigurationList = {config_list_proj} /* Build configuration list for PBXProject "Faraday" */;
			compatibilityVersion = "Xcode 14.0";
			developmentRegion = en;
			hasScannedForEncodings = 0;
			knownRegions = (
				en,
				Base,
			);
			mainGroup = {main_group};
			productRefGroup = {products} /* Products */;
			projectDirPath = "";
			projectRoot = "";
			targets = (
				{target} /* Faraday */,
			);
		}};"""
    )
    objects.append(
        f"""\t\t{sources_phase} /* Sources */ = {{
			isa = PBXSourcesBuildPhase;
			buildActionMask = 2147483647;
			files = (
{source_files}
			);
			runOnlyForDeploymentPostprocessing = 0;
		}};"""
    )
    objects.append(
        f"""\t\t{resources_phase} /* Resources */ = {{
			isa = PBXResourcesBuildPhase;
			buildActionMask = 2147483647;
			files = (
{resource_files}
			);
			runOnlyForDeploymentPostprocessing = 0;
		}};"""
    )
    objects.append(
        f"""\t\t{frameworks_phase} /* Frameworks */ = {{
			isa = PBXFrameworksBuildPhase;
			buildActionMask = 2147483647;
			files = (
			);
			runOnlyForDeploymentPostprocessing = 0;
		}};"""
    )

    common_proj = """
				ALWAYS_SEARCH_USER_PATHS = NO;
				CLANG_ENABLE_MODULES = YES;
				CLANG_ENABLE_OBJC_ARC = YES;
				COPY_PHASE_STRIP = NO;
				DEBUG_INFORMATION_FORMAT = dwarf;
				ENABLE_STRICT_OBJC_MSGSEND = YES;
				GCC_NO_COMMON_BLOCKS = YES;
				IPHONEOS_DEPLOYMENT_TARGET = 17.0;
				SDKROOT = iphoneos;
				SWIFT_VERSION = 5.0;
"""
    common_tgt = f"""
				ASSETCATALOG_COMPILER_APPICON_NAME = AppIcon;
				ASSETCATALOG_COMPILER_GLOBAL_ACCENT_COLOR_NAME = AccentColor;
				CODE_SIGN_STYLE = Automatic;
				CURRENT_PROJECT_VERSION = 1;
				GENERATE_INFOPLIST_FILE = NO;
				INFOPLIST_FILE = Faraday/Info.plist;
				LD_RUNPATH_SEARCH_PATHS = (
					"$(inherited)",
					"@executable_path/Frameworks",
				);
				MARKETING_VERSION = 1.0;
				PRODUCT_BUNDLE_IDENTIFIER = app.faraday.messenger;
				PRODUCT_NAME = "$(TARGET_NAME)";
				SUPPORTED_PLATFORMS = "iphoneos iphonesimulator";
				SUPPORTS_MACCATALYST = NO;
				SWIFT_EMIT_LOC_STRINGS = YES;
				SWIFT_STRICT_CONCURRENCY = targeted;
				SWIFT_VERSION = 5.0;
				TARGETED_DEVICE_FAMILY = "1,2";
"""

    objects.append(
        f"""\t\t{debug_proj} /* Debug */ = {{
			isa = XCBuildConfiguration;
			buildSettings = {{{common_proj}
				SWIFT_ACTIVE_COMPILATION_CONDITIONS = DEBUG;
				SWIFT_OPTIMIZATION_LEVEL = "-Onone";
			}};
			name = Debug;
		}};"""
    )
    objects.append(
        f"""\t\t{release_proj} /* Release */ = {{
			isa = XCBuildConfiguration;
			buildSettings = {{{common_proj}
				SWIFT_COMPILATION_MODE = wholemodule;
				SWIFT_OPTIMIZATION_LEVEL = "-O";
			}};
			name = Release;
		}};"""
    )
    objects.append(
        f"""\t\t{debug_tgt} /* Debug */ = {{
			isa = XCBuildConfiguration;
			buildSettings = {{{common_tgt}
				SWIFT_OPTIMIZATION_LEVEL = "-Onone";
			}};
			name = Debug;
		}};"""
    )
    objects.append(
        f"""\t\t{release_tgt} /* Release */ = {{
			isa = XCBuildConfiguration;
			buildSettings = {{{common_tgt}}};
			name = Release;
		}};"""
    )
    objects.append(
        f"""\t\t{config_list_proj} /* Build configuration list for PBXProject "Faraday" */ = {{
			isa = XCConfigurationList;
			buildConfigurations = (
				{debug_proj} /* Debug */,
				{release_proj} /* Release */,
			);
			defaultConfigurationIsVisible = 0;
			defaultConfigurationName = Release;
		}};"""
    )
    objects.append(
        f"""\t\t{config_list_tgt} /* Build configuration list for PBXNativeTarget "Faraday" */ = {{
			isa = XCConfigurationList;
			buildConfigurations = (
				{debug_tgt} /* Debug */,
				{release_tgt} /* Release */,
			);
			defaultConfigurationIsVisible = 0;
			defaultConfigurationName = Release;
		}};"""
    )

    return (
        "// !$*UTF8*$!\n{\n\tarchiveVersion = 1;\n\tclasses = {\n\t};\n\tobjectVersion = 56;\n\tobjects = {\n\n"
        + "\n".join(objects)
        + f"\n\t}};\n\trootObject = {project} /* Project object */;\n}}\n"
    )


def main() -> None:
    write_assets()
    PROJ.mkdir(parents=True, exist_ok=True)
    (PROJ / "project.pbxproj").write_text(pbxproj())
    print("wrote", PROJ / "project.pbxproj")


if __name__ == "__main__":
    main()
