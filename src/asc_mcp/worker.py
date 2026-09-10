import json
import os
import struct
import sys
import traceback
import xml.etree.ElementTree as ET

# Ensure repository root is on sys.path
_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)
if os.path.join(_REPO_ROOT, "src", "asc_core") not in sys.path:
    sys.path.insert(0, os.path.join(_REPO_ROOT, "src", "asc_core"))

_U32 = struct.Struct("<I")


def _format_access_flags(flags: int, is_method: bool = False, is_class: bool = False) -> list:
    res = []
    if flags & 0x0001:
        res.append("public")
    if flags & 0x0002:
        res.append("private")
    if flags & 0x0004:
        res.append("protected")
    if flags & 0x0008:
        res.append("static")
    if flags & 0x0010:
        res.append("final")
    if flags & 0x0020:
        res.append("synchronized" if is_method else "super")
    if flags & 0x0040:
        res.append("volatile" if not is_method else "bridge")
    if flags & 0x0080:
        res.append("transient" if not is_method else "varargs")
    if flags & 0x0100:
        res.append("native")
    if flags & 0x0200:
        res.append("interface")
    if flags & 0x0400:
        res.append("abstract")
    if flags & 0x0800:
        res.append("strictfp")
    if flags & 0x1000:
        res.append("synthetic")
    if flags & 0x4000:
        res.append("enum")
    return res


def _dalvik_to_dot(name: str) -> str:
    if name.startswith("L") and name.endswith(";"):
        return name[1:-1].replace("/", ".")
    return name


def _format_class_name(name: str) -> str:
    if not name:
        raise ValueError("Class name cannot be empty")
    if name.startswith("L") and name.endswith(";") and "/" in name:
        return name
    name = name.replace(".", "/")
    if not name.startswith("L"):
        name = f"L{name}"
    if not name.endswith(";"):
        name = f"{name};"
    return name


def handle_manifest(payload: dict) -> dict:
    from src.asc_client.manifest_handler import get_manifest_xml

    apk_path = payload["apk_path"]
    if not os.path.isfile(apk_path):
        raise FileNotFoundError(f"APK file not found: {apk_path}")

    raw_xml = payload.get("raw_xml", False)
    xml_text = get_manifest_xml(apk_path, pretty=True)

    if raw_xml:
        return {"apk_path": apk_path, "raw_xml": xml_text}

    # Parse structured summary
    root = ET.fromstring(xml_text)
    ns = {"android": "http://schemas.android.com/apk/res/android"}

    def get_attr(elem, name, default=""):
        return (
            elem.attrib.get(f"{{{ns['android']}}}{name}")
            or elem.attrib.get(name)
            or default
        )

    pkg = root.attrib.get("package", "")
    version_code = get_attr(root, "versionCode")
    version_name = get_attr(root, "versionName")

    uses_sdk = root.find("uses-sdk")
    min_sdk = get_attr(uses_sdk, "minSdkVersion") if uses_sdk is not None else ""
    target_sdk = get_attr(uses_sdk, "targetSdkVersion") if uses_sdk is not None else ""

    permissions = []
    for p in root.findall("uses-permission"):
        p_name = get_attr(p, "name")
        if p_name:
            permissions.append(p_name)

    app_elem = root.find("application")
    main_activity = None
    activities = []
    services = []
    receivers = []
    providers = []
    exported_components = []

    if app_elem is not None:
        for act in app_elem.findall("activity"):
            name = get_attr(act, "name")
            if not name:
                continue
            exported = get_attr(act, "exported")
            activities.append(name)

            is_main = False
            for ifilter in act.findall("intent-filter"):
                has_main = any(
                    get_attr(action, "name") == "android.intent.action.MAIN"
                    for action in ifilter.findall("action")
                )
                has_launcher = any(
                    get_attr(category, "name") == "android.intent.category.LAUNCHER"
                    for category in ifilter.findall("category")
                )
                if has_main and has_launcher:
                    is_main = True
                    main_activity = name
                    break

            if exported == "true" or (exported == "" and is_main):
                exported_components.append({"type": "activity", "name": name})

        for s in app_elem.findall("service"):
            name = get_attr(s, "name")
            if name:
                services.append(name)
                if get_attr(s, "exported") == "true":
                    exported_components.append({"type": "service", "name": name})

        for r in app_elem.findall("receiver"):
            name = get_attr(r, "name")
            if name:
                receivers.append(name)
                if get_attr(r, "exported") == "true":
                    exported_components.append({"type": "receiver", "name": name})

        for pr in app_elem.findall("provider"):
            name = get_attr(pr, "name")
            if name:
                providers.append(name)
                if get_attr(pr, "exported") == "true":
                    exported_components.append({"type": "provider", "name": name})

    return {
        "apk_path": apk_path,
        "package": pkg,
        "version_code": version_code,
        "version_name": version_name,
        "min_sdk_version": min_sdk,
        "target_sdk_version": target_sdk,
        "main_activity": main_activity,
        "permissions_count": len(permissions),
        "permissions": permissions,
        "activities_count": len(activities),
        "activities": activities[:50],
        "services_count": len(services),
        "services": services[:50],
        "receivers_count": len(receivers),
        "receivers": receivers[:50],
        "providers_count": len(providers),
        "providers": providers[:50],
        "exported_components": exported_components,
    }


def handle_list_classes(payload: dict) -> dict:
    import mmap
    from src.asc_client.apk_handler import _parse_cd_dex_entries, _inflate_dex
    from src.asc_client.dex_container import iter_logical_dex_buffers
    from src.asc_core.utils.tinydex import DEX

    apk_path = payload["apk_path"]
    query = (payload.get("query") or "").strip().lower()
    prefix = (payload.get("package_prefix") or "").strip()
    limit = max(1, min(int(payload.get("limit", 50)), 200))

    if not os.path.isfile(apk_path):
        raise FileNotFoundError(f"APK file not found: {apk_path}")

    all_classes = set()
    with open(apk_path, "rb") as fp:
        with mmap.mmap(fp.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            entries = _parse_cd_dex_entries(mm)
            for entry in entries:
                data = _inflate_dex(mm, entry)
                if data is None:
                    continue
                for _dex_name, dex_buf in iter_logical_dex_buffers(entry[0], data):
                    dex = DEX.parse(memoryview(dex_buf), entry[0])
                    for i in range(len(dex.classes)):
                        all_classes.add(dex.classes[i].fullname)

    dot_classes = sorted(_dalvik_to_dot(c) for c in all_classes)
    total_classes = len(dot_classes)

    matched = []
    for c in dot_classes:
        if prefix and not c.startswith(prefix):
            continue
        if query and query not in c.lower():
            continue
        matched.append(c)

    return {
        "apk_path": apk_path,
        "total_classes": total_classes,
        "matched_count": len(matched),
        "classes": matched[:limit],
        "truncated": len(matched) > limit,
    }


def handle_outline(payload: dict) -> dict:
    from src.asc_client.apk_handler import ApkHandler
    from src.asc_core.utils.tinydex import DEX

    apk_path = payload["apk_path"]
    class_name = payload["class_name"]
    dalvik_class = _format_class_name(class_name)

    if not os.path.isfile(apk_path):
        raise FileNotFoundError(f"APK file not found: {apk_path}")

    handler = ApkHandler(apk_path)
    hit = handler.get_class_dex(dalvik_class)
    if hit is None:
        raise ValueError(f"Class {dalvik_class} not found in APK: {apk_path}")

    dex_name, dex_buf = hit
    dex = DEX.parse(memoryview(dex_buf), dex_name)
    clazz = dex.get_class(dalvik_class)
    if clazz is None:
        raise ValueError(f"Failed to resolve class {dalvik_class} in {dex_name}")

    # Access flags and superclass
    class_def_off = clazz._class_def_off
    access_flags_raw = _U32.unpack_from(dex.buf, class_def_off + 4)[0]
    superclass_idx = _U32.unpack_from(dex.buf, class_def_off + 8)[0]
    superclass = (
        _dalvik_to_dot(dex.get_type(superclass_idx).descriptor)
        if superclass_idx != 0xFFFFFFFF
        else None
    )

    # Interfaces
    interfaces_off = _U32.unpack_from(dex.buf, class_def_off + 12)[0]
    interfaces = []
    if interfaces_off > 0:
        ifs_size = _U32.unpack_from(dex.buf, interfaces_off)[0]
        off = interfaces_off + 4
        for _ in range(ifs_size):
            type_idx = struct.unpack_from("<H", dex.buf, off)[0]
            off += 2
            interfaces.append(_dalvik_to_dot(dex.get_type(type_idx).descriptor))

    # Fields
    fields_list = []
    for f in clazz.fields:
        f_flags = _format_access_flags(f.access_flags)
        fields_list.append({
            "name": f.name,
            "type": _dalvik_to_dot(f.type.descriptor),
            "access": " ".join(f_flags),
        })

    # Methods
    methods_list = []
    for m in clazz.methods:
        proto = m.prototype
        params = [_dalvik_to_dot(t.descriptor) for t in proto.parameters_type]
        ret_type = _dalvik_to_dot(dex.get_type(proto.return_type_idx).descriptor)
        m_flags = _format_access_flags(m.access_flags, is_method=True)
        methods_list.append({
            "name": m.name,
            "parameters": params,
            "return_type": ret_type,
            "signature": f"{m.name}({', '.join(params)}) -> {ret_type}",
            "access": " ".join(m_flags),
        })

    return {
        "dex_name": dex_name,
        "class_name": _dalvik_to_dot(clazz.fullname),
        "dalvik_class": clazz.fullname,
        "access": " ".join(_format_access_flags(access_flags_raw, is_class=True)),
        "superclass": superclass,
        "interfaces": interfaces,
        "fields_count": len(fields_list),
        "fields": fields_list,
        "methods_count": len(methods_list),
        "methods": methods_list,
    }


def handle_getclass(payload: dict) -> dict:
    from src.asc_client.apk_handler import ApkHandler
    from src.asc_client.asc_handler import AscHandler
    from src.asc_client.gui.text_utils import decode_java_unicode_escapes

    apk_path = payload["apk_path"]
    class_name = payload["class_name"]
    dalvik_class = _format_class_name(class_name)

    if not os.path.isfile(apk_path):
        raise FileNotFoundError(f"APK file not found: {apk_path}")

    handler = ApkHandler(apk_path)
    hit = handler.get_class_dex(dalvik_class)
    if hit is None:
        raise ValueError(f"Class {dalvik_class} not found in APK: {apk_path}")

    dex_name, dex_buf = hit
    asc = AscHandler(debug=False)
    raw_source = asc.getclass(dex_buf, dalvik_class)
    source = decode_java_unicode_escapes(raw_source)

    return {
        "dex_name": dex_name,
        "class_name": _dalvik_to_dot(dalvik_class),
        "dalvik_class": dalvik_class,
        "source": source,
    }


def handle_list_methods(payload: dict) -> dict:
    import mmap
    from src.asc_client.apk_handler import _parse_cd_dex_entries, _inflate_dex
    from src.asc_client.dex_container import iter_logical_dex_buffers
    from src.asc_core.utils.tinydex import DEX
    from src.asc_core.findrefs.findrefs_manager import FindRefManager

    apk_path = payload["apk_path"]
    query = (payload.get("query") or "").strip()
    class_name = (payload.get("class_name") or "").strip()
    limit = max(1, min(int(payload.get("limit", 50)), 200))

    if not os.path.isfile(apk_path):
        raise FileNotFoundError(f"APK file not found: {apk_path}")
    if not query and not class_name:
        raise ValueError("At least one of 'query' (method name) or 'class_name' must be provided.")

    methods = []
    with open(apk_path, "rb") as fp:
        with mmap.mmap(fp.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            entries = _parse_cd_dex_entries(mm)
            for entry in entries:
                data = _inflate_dex(mm, entry)
                if data is None:
                    continue
                for dex_name, dex_buf in iter_logical_dex_buffers(entry[0], data):
                    dex = DEX.parse(memoryview(dex_buf), dex_name)
                    manager = FindRefManager(dex)
                    locator = manager._get_method_locator(True)
                    clz = None
                    if class_name:
                        clz = _format_class_name(class_name)
                    located = locator.locate({"class": [clz, True] if clz else None, "method": query or None})
                    for midx in sorted(located):
                        method = dex.methods[midx]
                        cls_fullname = method.cls.fullname
                        proto = method.prototype
                        params = [_dalvik_to_dot(t.descriptor) for t in proto.parameters_type]
                        ret_type = _dalvik_to_dot(dex.get_type(proto.return_type_idx).descriptor)
                        access = _format_access_flags(method.access_flags, is_method=True)
                        methods.append({
                            "dex": dex_name,
                            "class": _dalvik_to_dot(cls_fullname),
                            "dalvik_class": cls_fullname,
                            "name": method.name,
                            "signature": f"{method.name}({', '.join(params)}) -> {ret_type}",
                            "parameters": params,
                            "return_type": ret_type,
                            "access": " ".join(access),
                        })

    total = len(methods)
    return {
        "apk_path": apk_path,
        "query": query,
        "class_name": class_name,
        "total_matches": total,
        "truncated": total > limit,
        "methods": methods[:limit],
    }


def handle_search_strings(payload: dict) -> dict:
    import mmap
    from src.asc_client.apk_handler import _parse_cd_dex_entries, _inflate_dex
    from src.asc_client.dex_container import iter_logical_dex_buffers
    from src.asc_core.utils.tinydex import DEX
    from src.asc_core.findrefs.findrefs_manager import FindRefManager

    apk_path = payload["apk_path"]
    pattern = (payload.get("pattern") or "").strip()
    limit = max(1, min(int(payload.get("limit", 50)), 500))

    if not os.path.isfile(apk_path):
        raise FileNotFoundError(f"APK file not found: {apk_path}")
    if not pattern:
        raise ValueError("'pattern' (regex or substring) must be provided.")

    results = []
    seen = set()
    with open(apk_path, "rb") as fp:
        with mmap.mmap(fp.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            entries = _parse_cd_dex_entries(mm)
            for entry in entries:
                data = _inflate_dex(mm, entry)
                if data is None:
                    continue
                for dex_name, dex_buf in iter_logical_dex_buffers(entry[0], data):
                    dex = DEX.parse(memoryview(dex_buf), dex_name)
                    manager = FindRefManager(dex)
                    locator = manager._get_str_locator(True)
                    str_idxs = locator.locate(pattern)
                    for idx in sorted(str_idxs):
                        val = dex.strings[idx]
                        if val in seen:
                            continue
                        seen.add(val)
                        results.append(val)

    total = len(results)
    return {
        "apk_path": apk_path,
        "pattern": pattern,
        "total_matches": total,
        "truncated": total > limit,
        "strings": results[:limit],
    }


def handle_list_native_libs(payload: dict) -> dict:
    import zipfile

    apk_path = payload["apk_path"]
    if not os.path.isfile(apk_path):
        raise FileNotFoundError(f"APK file not found: {apk_path}")

    libs = []
    with zipfile.ZipFile(apk_path, "r") as zf:
        for info in zf.infolist():
            if info.filename.startswith("lib/") and info.filename.endswith(".so"):
                parts = info.filename.split("/")
                arch = parts[1] if len(parts) >= 3 else "unknown"
                libs.append({
                    "path": info.filename,
                    "name": parts[-1],
                    "arch": arch,
                    "size": info.file_size,
                })

    libs.sort(key=lambda x: (x["arch"], x["name"]))
    archs = sorted(set(lib["arch"] for lib in libs))
    return {
        "apk_path": apk_path,
        "total_libs": len(libs),
        "architectures": archs,
        "libs": libs,
    }


def handle_extract_dex(payload: dict) -> dict:
    import mmap as mmap_mod
    from src.asc_client.apk_handler import _parse_cd_dex_entries, _inflate_dex

    apk_path = payload["apk_path"]
    output_path = payload.get("output_path")
    dex_name_filter = (payload.get("dex_name") or "").strip()

    if not os.path.isfile(apk_path):
        raise FileNotFoundError(f"APK file not found: {apk_path}")

    with open(apk_path, "rb") as fp:
        with mmap_mod.mmap(fp.fileno(), 0, access=mmap_mod.ACCESS_READ) as mm:
            entries = _parse_cd_dex_entries(mm)
            if not entries:
                raise ValueError("No DEX entries found in APK.")

            if dex_name_filter:
                matches = [e for e in entries if e[0] == dex_name_filter]
                if not matches:
                    available = [e[0] for e in entries]
                    raise ValueError(f"DEX '{dex_name_filter}' not found. Available: {available}")
                entries = matches

            exported = []
            for entry in entries:
                data = _inflate_dex(mm, entry)
                if data is None:
                    continue

                if output_path:
                    out = os.path.join(output_path, entry[0])
                    os.makedirs(output_path, exist_ok=True)
                else:
                    out = entry[0]

                with open(out, "wb") as wf:
                    wf.write(data)
                exported.append({
                    "dex_name": entry[0],
                    "output": out,
                    "size": len(data),
                })

    return {
        "apk_path": apk_path,
        "exported_count": len(exported),
        "exported": exported,
    }


def handle_findrefs(payload: dict) -> dict:
    from src.asc_client.apk_handler import ApkHandler
    from src.asc_client.gui.runtime import build_find_query, parse_result_line

    apk_path = payload["apk_path"]
    find_type = payload["find_type"].strip().lower()
    query = payload["query"].strip()
    class_name = payload.get("class_name")
    fuzzy_class = bool(payload.get("fuzzy_class", False))
    limit = max(1, min(int(payload.get("limit", 30)), 100))

    if not os.path.isfile(apk_path):
        raise FileNotFoundError(f"APK file not found: {apk_path}")

    if find_type not in ("string", "type", "method", "field"):
        raise ValueError(f"Invalid find_type: {find_type}. Must be one of string, type, method, field.")

    find_key, find_dict = build_find_query(find_type, query, class_name, fuzzy_class)
    apk_handler = ApkHandler(apk_path)

    references = []
    for _dex_name, lines in apk_handler.for_each_findrefs(find_key, find_dict):
        for line in lines:
            if not line:
                continue
            item = parse_result_line(line)
            references.append({
                "dex": item["dex_name"],
                "caller_class": item["class_display"],
                "caller_method": item["method_text"],
                "matched": item["matched_text"],
            })

    total_matches = len(references)
    return {
        "apk_path": apk_path,
        "find_type": find_type,
        "query": query,
        "total_matches": total_matches,
        "truncated": total_matches > limit,
        "references": references[:limit],
    }


def handle_list_resources(payload: dict) -> dict:
    import zipfile

    apk_path = payload["apk_path"]
    prefix = (payload.get("prefix") or "").strip()
    limit = max(1, min(int(payload.get("limit", 100)), 500))

    if not os.path.isfile(apk_path):
        raise FileNotFoundError(f"APK file not found: {apk_path}")

    summary = {"res": 0, "assets": 0, "lib": 0, "meta_inf": 0, "other": 0}
    res_breakdown = {}
    files = []

    with zipfile.ZipFile(apk_path, "r") as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            path = info.filename

            if prefix and not path.startswith(prefix):
                continue

            if path.startswith("res/"):
                category = "res"
                summary["res"] += 1
                parts = path.split("/")
                if len(parts) >= 2:
                    subdir = parts[1]
                    res_breakdown[subdir] = res_breakdown.get(subdir, 0) + 1
            elif path.startswith("assets/"):
                category = "assets"
                summary["assets"] += 1
            elif path.startswith("lib/"):
                category = "lib"
                summary["lib"] += 1
            elif path.startswith("META-INF/"):
                category = "meta_inf"
                summary["meta_inf"] += 1
            else:
                category = "other"
                summary["other"] += 1

            if len(files) < limit:
                files.append({
                    "path": path,
                    "size": info.file_size,
                    "category": category,
                })

    total = sum(summary.values())
    return {
        "apk_path": apk_path,
        "total_entries": total,
        "summary": summary,
        "res_breakdown": dict(sorted(res_breakdown.items(), key=lambda x: -x[1])),
        "files_count": len(files),
        "truncated": len(files) < total,
        "files": files,
    }


def handle_get_string_constants(payload: dict) -> dict:
    from src.asc_client.apk_handler import ApkHandler
    from src.asc_core.utils.tinydex import DEX
    from models.dvm_opcode import opcodes, Format

    apk_path = payload["apk_path"]
    class_name = payload["class_name"]
    limit = max(1, min(int(payload.get("limit", 100)), 500))
    dalvik_class = _format_class_name(class_name)

    if not os.path.isfile(apk_path):
        raise FileNotFoundError(f"APK file not found: {apk_path}")

    handler = ApkHandler(apk_path)
    hit = handler.get_class_dex(dalvik_class)
    if hit is None:
        raise ValueError(f"Class {dalvik_class} not found in APK: {apk_path}")

    dex_name, dex_buf = hit
    dex = DEX.parse(memoryview(dex_buf), dex_name)
    clazz = dex.get_class(dalvik_class)
    if clazz is None:
        raise ValueError(f"Failed to resolve class {dalvik_class} in {dex_name}")

    WORD = 2
    _H = struct.Struct("<H")
    _I = struct.Struct("<I")

    seen = set()
    methods_result = []
    total_strings = 0

    for method in clazz.methods:
        bytecode = method.bytecode
        if not bytecode:
            continue
        bc = bytecode
        bc_len = len(bc)
        strings = []
        pc = 0
        while pc < bc_len:
            opcode = bc[pc]
            if opcode not in opcodes:
                break
            op = opcodes[opcode]
            if op.idx and op.idx.name == "kIndexStringRef":
                idx_off = pc + 2
                if op.fmt == Format.k31c:
                    if idx_off + 4 <= bc_len:
                        idx = _I.unpack_from(bytes(bc[idx_off:idx_off + 4]))[0]
                    else:
                        pc += op.oplen * WORD
                        continue
                else:
                    if idx_off + 2 <= bc_len:
                        idx = _H.unpack_from(bytes(bc[idx_off:idx_off + 2]))[0]
                    else:
                        pc += op.oplen * WORD
                        continue
                try:
                    val = dex.strings[idx]
                except (IndexError, KeyError):
                    pc += op.oplen * WORD
                    continue
                if val not in seen:
                    seen.add(val)
                    strings.append(val)
            pc += op.oplen * WORD

        if strings:
            methods_result.append({
                "method": method.name,
                "strings": strings,
            })
            total_strings += len(strings)

    return {
        "apk_path": apk_path,
        "class_name": _dalvik_to_dot(dalvik_class),
        "dalvik_class": dalvik_class,
        "total_strings": total_strings,
        "truncated": total_strings > limit,
        "methods": methods_result,
    }


SECRET_PATTERNS = {
    "aws_access_key": {
        "pattern": r"AKIA[0-9A-Z]{16}",
        "severity": "high",
        "description": "AWS Access Key ID",
    },
    "google_api_key": {
        "pattern": r"AIza[0-9A-Za-z\-_]{35}",
        "severity": "high",
        "description": "Google API Key",
    },
    "firebase_url": {
        "pattern": r"https://[a-z0-9-]+\.firebaseio\.com",
        "severity": "medium",
        "description": "Firebase Database URL",
    },
    "generic_api_key": {
        "pattern": r"(?i)(api[_\-]?key|apikey|api[_\-]?secret)['\"]?\s*[:=]\s*['\"][0-9a-zA-Z\-_]{20,}['\"]",
        "severity": "high",
        "description": "Generic API Key assignment",
    },
    "generic_secret": {
        "pattern": r"(?i)(secret|token)['\"]?\s*[:=]\s*['\"][0-9a-zA-Z\-_+/]{16,}['\"]",
        "severity": "high",
        "description": "Generic Secret/Token assignment",
    },
    "hardcoded_password": {
        "pattern": r"(?i)(password|passwd|pwd)['\"]?\s*[:=]\s*['\"][^\'\"]{4,}['\"]",
        "severity": "high",
        "description": "Hardcoded Password",
    },
    "jwt_token": {
        "pattern": r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
        "severity": "high",
        "description": "JWT Token",
    },
    "private_key_header": {
        "pattern": r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----",
        "severity": "critical",
        "description": "Private Key Header",
    },
    "slack_token": {
        "pattern": r"xox[baprs]-[0-9]{10,}-[a-zA-Z0-9-]+",
        "severity": "high",
        "description": "Slack Token",
    },
    "github_token": {
        "pattern": r"gh[ps]_[A-Za-z0-9_]{36,}",
        "severity": "high",
        "description": "GitHub Token",
    },
    "telegram_bot_token": {
        "pattern": r"[0-9]{8,10}:[A-Za-z0-9_-]{35}",
        "severity": "high",
        "description": "Telegram Bot Token",
    },
    "base64_secret_assignment": {
        "pattern": r"(?i)(secret|key|token|password).{0,20}['\"][A-Za-z0-9+/]{40,}={0,2}['\"]",
        "severity": "medium",
        "description": "Base64-encoded Secret Assignment",
    },
    "ip_with_port": {
        "pattern": r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{2,5}\b",
        "severity": "low",
        "description": "Hardcoded IP:Port",
    },
    "http_with_credentials": {
        "pattern": r"https?://[^/\s]+:[^/\s]+@[^/\s]+",
        "severity": "high",
        "description": "URL with Embedded Credentials",
    },
    "jdbc_connection_string": {
        "pattern": r"jdbc:[a-z]+://[^\s\"']+",
        "severity": "medium",
        "description": "JDBC Connection String",
    },
    "aws_secret_key": {
        "pattern": r"(?i)aws[_\-]?secret[_\-]?access[_\-]?key['\"]?\s*[:=]\s*['\"][0-9a-zA-Z/+]{40}['\"]",
        "severity": "high",
        "description": "AWS Secret Access Key",
    },
}


def handle_scan_secrets(payload: dict) -> dict:
    import mmap as mmap_mod
    from src.asc_client.apk_handler import _parse_cd_dex_entries, _inflate_dex
    from src.asc_client.dex_container import iter_logical_dex_buffers
    from src.asc_core.utils.tinydex import DEX
    from src.asc_core.findrefs.findrefs_manager import FindRefManager

    apk_path = payload["apk_path"]
    pattern_names = payload.get("patterns")
    limit = max(1, min(int(payload.get("limit", 100)), 500))

    if not os.path.isfile(apk_path):
        raise FileNotFoundError(f"APK file not found: {apk_path}")

    if pattern_names:
        active_patterns = {}
        for name in pattern_names:
            if name not in SECRET_PATTERNS:
                raise ValueError(f"Unknown pattern: {name}. Available: {list(SECRET_PATTERNS.keys())}")
            active_patterns[name] = SECRET_PATTERNS[name]
    else:
        active_patterns = SECRET_PATTERNS

    findings = []
    seen_values = set()

    with open(apk_path, "rb") as fp:
        with mmap_mod.mmap(fp.fileno(), 0, access=mmap_mod.ACCESS_READ) as mm:
            entries = _parse_cd_dex_entries(mm)
            for entry in entries:
                data = _inflate_dex(mm, entry)
                if data is None:
                    continue
                for dex_name, dex_buf in iter_logical_dex_buffers(entry[0], data):
                    dex = DEX.parse(memoryview(dex_buf), dex_name)
                    manager = FindRefManager(dex)
                    locator = manager._get_str_locator(True)

                    for pattern_name, pattern_info in active_patterns.items():
                        str_idxs = locator.locate(pattern_info["pattern"])
                        for idx in sorted(str_idxs):
                            val = dex.strings[idx]
                            key = (pattern_name, val)
                            if key in seen_values:
                                continue
                            seen_values.add(key)
                            findings.append({
                                "pattern": pattern_name,
                                "severity": pattern_info["severity"],
                                "description": pattern_info["description"],
                                "value": val,
                                "dex": dex_name,
                            })

    # Also scan AndroidManifest.xml for secrets (API keys, etc.)
    try:
        import re as _re
        from src.asc_client.manifest_handler import get_manifest_xml
        manifest_xml = get_manifest_xml(apk_path)
        for pattern_name, pattern_info in active_patterns.items():
            for m in _re.finditer(pattern_info["pattern"], manifest_xml):
                val = m.group(0)
                key = (pattern_name, val)
                if key in seen_values:
                    continue
                seen_values.add(key)
                findings.append({
                    "pattern": pattern_name,
                    "severity": pattern_info["severity"],
                    "description": pattern_info["description"],
                    "value": val,
                    "dex": "AndroidManifest.xml",
                })
    except Exception:
        pass

    total = len(findings)
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda x: severity_order.get(x["severity"], 99))

    return {
        "apk_path": apk_path,
        "total_findings": total,
        "patterns_checked": len(active_patterns),
        "truncated": total > limit,
        "findings": findings[:limit],
    }


def handle_disassemble_method(payload: dict) -> dict:
    import struct as struct_mod
    from src.asc_client.apk_handler import ApkHandler
    from src.asc_core.utils.tinydex import DEX
    from src.asc_core.utils.smali_renderer import render_smali

    apk_path = payload["apk_path"]
    class_name = payload["class_name"]
    method_name = (payload.get("method_name") or "").strip()
    method_signature = (payload.get("method_signature") or "").strip()
    dalvik_class = _format_class_name(class_name)

    if not os.path.isfile(apk_path):
        raise FileNotFoundError(f"APK file not found: {apk_path}")
    if not method_name:
        raise ValueError("'method_name' must be provided.")

    handler = ApkHandler(apk_path)
    hit = handler.get_class_dex(dalvik_class)
    if hit is None:
        raise ValueError(f"Class {dalvik_class} not found in APK: {apk_path}")

    dex_name, dex_buf = hit
    dex = DEX.parse(memoryview(dex_buf), dex_name)
    clazz = dex.get_class(dalvik_class)
    if clazz is None:
        raise ValueError(f"Failed to resolve class {dalvik_class} in {dex_name}")

    target_method = None
    for m in clazz.methods:
        if m.name != method_name:
            continue
        if method_signature:
            proto = m.prototype
            params = [_dalvik_to_dot(t.descriptor) for t in proto.parameters_type]
            ret_type = _dalvik_to_dot(dex.get_type(proto.return_type_idx).descriptor)
            sig = f"{m.name}({', '.join(params)}) -> {ret_type}"
            if method_signature not in sig:
                continue
        target_method = m
        break

    if target_method is None:
        available = [m.name for m in clazz.methods]
        raise ValueError(f"Method '{method_name}' not found in {dalvik_class}. Available: {available}")

    _HHHHII = struct_mod.Struct("<HHHHII")
    code_off = target_method._code_off
    registers_size = ins_size = outs_size = tries_size = insns_size = 0
    if code_off > 0:
        registers_size, ins_size, outs_size, tries_size, _debug_info_off, insns_size = _HHHHII.unpack_from(dex.buf, code_off)

    bytecode = target_method.bytecode
    proto = target_method.prototype
    params = [_dalvik_to_dot(t.descriptor) for t in proto.parameters_type]
    ret_type = _dalvik_to_dot(dex.get_type(proto.return_type_idx).descriptor)
    access = _format_access_flags(target_method.access_flags, is_method=True)
    access_str = " ".join(access) if access else ""

    smali_header = f".method {access_str} {method_name}({', '.join(params)}){ret_type}"
    smali_lines = render_smali(bytecode, dex)

    full_smali = [smali_header, f"    .registers {registers_size}"]
    full_smali.extend(smali_lines)
    full_smali.append(".end method")

    return {
        "apk_path": apk_path,
        "dex_name": dex_name,
        "class_name": _dalvik_to_dot(dalvik_class),
        "dalvik_class": dalvik_class,
        "method_name": method_name,
        "signature": f"{method_name}({', '.join(params)}) -> {ret_type}",
        "access": access_str,
        "registers": registers_size,
        "ins": ins_size,
        "outs": outs_size,
        "tries": tries_size,
        "insns_count": insns_size,
        "smali": full_smali,
    }


def handle_get_certificate(payload: dict) -> dict:
    import zipfile
    from asn1crypto import cms
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes

    apk_path = payload["apk_path"]
    if not os.path.isfile(apk_path):
        raise FileNotFoundError(f"APK file not found: {apk_path}")

    sig_entry = None
    sig_data = None
    with zipfile.ZipFile(apk_path, "r") as zf:
        for name in zf.namelist():
            upper = name.upper()
            if upper.startswith("META-INF/") and (
                upper.endswith(".RSA") or upper.endswith(".DSA") or upper.endswith(".EC")
            ):
                sig_data = zf.read(name)
                sig_entry = name
                break

    if sig_data is None:
        raise ValueError("No V1 signing certificate found (META-INF/*.RSA/*.DSA/*.EC)")

    content_info = cms.ContentInfo.load(sig_data)
    signed_data = content_info["content"]
    certs = signed_data["certificates"]

    results = []
    for cert_choice in certs:
        cert_der = cert_choice.dump()
        cert = x509.load_der_x509_certificate(cert_der)

        key = cert.public_key()
        key_type = type(key).__name__
        key_size = getattr(key, "key_size", 0)

        sig_alg = cert.signature_algorithm_oid._name
        if not sig_alg or sig_alg.startswith("Unknown"):
            sig_alg = cert.signature_algorithm_oid.dotted_string

        results.append({
            "subject": cert.subject.rfc4514_string(),
            "issuer": cert.issuer.rfc4514_string(),
            "serial_number": str(cert.serial_number),
            "not_valid_before": cert.not_valid_before_utc.isoformat(),
            "not_valid_after": cert.not_valid_after_utc.isoformat(),
            "signature_algorithm": sig_alg,
            "public_key_type": key_type,
            "public_key_size": key_size,
            "fingerprint_sha256": cert.fingerprint(hashes.SHA256()).hex(":"),
            "fingerprint_sha1": cert.fingerprint(hashes.SHA1()).hex(":"),
        })

    return {
        "apk_path": apk_path,
        "signature_entry": sig_entry,
        "certificate_count": len(results),
        "certificates": results,
    }


def _format_method_sig(method, dex) -> str:
    proto = method.prototype
    params = ",".join(t.descriptor for t in proto.parameters_type)
    ret = dex.get_type(proto.return_type_idx).descriptor
    return f"{method.name}({params}){ret}"


def handle_call_graph(payload: dict) -> dict:
    import mmap as mmap_mod
    from src.asc_client.apk_handler import ApkHandler, _parse_cd_dex_entries, _inflate_dex
    from src.asc_client.dex_container import iter_logical_dex_buffers
    from src.asc_core.utils.tinydex import DEX
    from src.asc_core.findrefs.findrefs_manager import FindRefManager
    from models.dvm_opcode import opcodes as _opcodes, IndexFlag

    apk_path = payload["apk_path"]
    class_name = payload["class_name"]
    method_name = (payload.get("method_name") or "").strip()
    method_signature = (payload.get("method_signature") or "").strip()
    direction = payload.get("direction", "both")
    depth = max(1, min(int(payload.get("depth", 1)), 5))
    dalvik_class = _format_class_name(class_name)

    if not os.path.isfile(apk_path):
        raise FileNotFoundError(f"APK file not found: {apk_path}")
    if not method_name:
        raise ValueError("'method_name' must be provided.")
    if direction not in ("callers", "callees", "both"):
        raise ValueError("direction must be one of: callers, callees, both")

    # Locate target method
    handler = ApkHandler(apk_path)
    hit = handler.get_class_dex(dalvik_class)
    if hit is None:
        raise ValueError(f"Class {dalvik_class} not found in APK: {apk_path}")

    dex_name, dex_buf = hit
    dex = DEX.parse(memoryview(dex_buf), dex_name)
    clazz = dex.get_class(dalvik_class)
    if clazz is None:
        raise ValueError(f"Failed to resolve class {dalvik_class}")

    target_method = None
    for m in clazz.methods:
        if m.name != method_name:
            continue
        if method_signature:
            sig = _format_method_sig(m, dex)
            if method_signature not in sig:
                continue
        target_method = m
        break

    if target_method is None:
        available = list({m.name for m in clazz.methods})
        raise ValueError(f"Method '{method_name}' not found. Available: {available}")

    target_sig = _format_method_sig(target_method, dex)
    target_info = {
        "class": _dalvik_to_dot(dalvik_class),
        "method": method_name,
        "signature": target_sig,
    }

    def get_callees(d, method):
        callees = []
        bc = method.bytecode
        if not bc:
            return callees
        bc_len = len(bc)
        seen = set()
        pc = 0
        while pc < bc_len:
            opcode = bc[pc]
            if opcode not in _opcodes:
                break
            op = _opcodes[opcode]
            if op.idx in (IndexFlag.kIndexMethodRef, IndexFlag.kIndexMethodAndProtoRef):
                idx = bc[pc + 2] | (bc[pc + 3] << 8)
                if idx not in seen:
                    seen.add(idx)
                    try:
                        callee = d.methods[idx]
                        callees.append({
                            "class": _dalvik_to_dot(callee.cls.fullname),
                            "method": callee.name,
                            "signature": _format_method_sig(callee, d),
                            "invoke_type": op.name,
                        })
                    except (IndexError, KeyError):
                        pass
            pc += op.oplen * 2
        return callees

    def get_callers_single_dex(d, d_buf, d_name):
        m = FindRefManager(d)
        loc = m._get_method_locator(True)
        mids = loc.locate({"class": [dalvik_class, True], "method": method_name})
        if not mids:
            return []
        find = {"method": set(mids)}
        m._get_code_scanner().scan(find)
        caller_mids = set(x for x in find["method"] if x is not None)
        results = []
        for cmid in sorted(caller_mids):
            cm = d.methods[cmid]
            results.append({
                "class": _dalvik_to_dot(cm.cls.fullname),
                "method": cm.name,
                "signature": _format_method_sig(cm, d),
                "invoke_type": "",
            })
        return results

    def get_callers_all():
        callers = []
        seen_classes = set()
        with open(apk_path, "rb") as fp:
            with mmap_mod.mmap(fp.fileno(), 0, access=mmap_mod.ACCESS_READ) as mm:
                entries = _parse_cd_dex_entries(mm)
                for entry in entries:
                    data = _inflate_dex(mm, entry)
                    if data is None:
                        continue
                    for d_name, d_buf in iter_logical_dex_buffers(entry[0], data):
                        d = DEX.parse(memoryview(d_buf), d_name)
                        for c in get_callers_single_dex(d, d_buf, d_name):
                            key = (c["class"], c["method"], c["signature"])
                            if key not in seen_classes:
                                seen_classes.add(key)
                                callers.append(c)
        return callers

    callers = []
    callees = []

    if direction in ("callers", "both"):
        callers = get_callers_all()
    if direction in ("callees", "both"):
        callees = get_callees(dex, target_method)

    return {
        "apk_path": apk_path,
        "target": target_info,
        "depth": depth,
        "direction": direction,
        "callers_count": len(callers),
        "callees_count": len(callees),
        "callers": callers,
        "callees": callees,
    }


def _collect_all_methods(apk_path: str) -> dict:
    import mmap as mmap_mod
    from src.asc_client.apk_handler import _parse_cd_dex_entries, _inflate_dex
    from src.asc_client.dex_container import iter_logical_dex_buffers
    from src.asc_core.utils.tinydex import DEX

    result = {}
    with open(apk_path, "rb") as fp:
        with mmap_mod.mmap(fp.fileno(), 0, access=mmap_mod.ACCESS_READ) as mm:
            entries = _parse_cd_dex_entries(mm)
            for entry in entries:
                data = _inflate_dex(mm, entry)
                if data is None:
                    continue
                for dex_name, dex_buf in iter_logical_dex_buffers(entry[0], data):
                    dex = DEX.parse(memoryview(dex_buf), dex_name)
                    for i in range(len(dex.classes)):
                        clazz = dex.classes[i]
                        cls_name = clazz.fullname
                        sigs = set()
                        for m in clazz.methods:
                            sigs.add(_format_method_sig(m, dex))
                        result.setdefault(cls_name, set()).update(sigs)
    return result


def handle_apk_diff(payload: dict) -> dict:
    import hashlib
    import difflib
    import mmap as mmap_mod
    from src.asc_client.apk_handler import ApkHandler, _parse_cd_dex_entries, _inflate_dex
    from src.asc_client.dex_container import iter_logical_dex_buffers
    from src.asc_core.utils.tinydex import DEX
    from src.asc_core.utils.smali_renderer import render_smali

    old_apk = payload["old_apk"]
    new_apk = payload["new_apk"]
    level = max(1, min(int(payload.get("level", 2)), 3))
    prefix = (payload.get("package_prefix") or "").strip()
    limit = max(1, min(int(payload.get("limit", 50)), 200))

    for p in (old_apk, new_apk):
        if not os.path.isfile(p):
            raise FileNotFoundError(f"APK file not found: {p}")

    # --- collect class sets ---
    def collect_classes(apk_path):
        classes = set()
        with open(apk_path, "rb") as fp:
            with mmap_mod.mmap(fp.fileno(), 0, access=mmap_mod.ACCESS_READ) as mm:
                for entry in _parse_cd_dex_entries(mm):
                    data = _inflate_dex(mm, entry)
                    if data is None:
                        continue
                    for dex_name, dex_buf in iter_logical_dex_buffers(entry[0], data):
                        dex = DEX.parse(memoryview(dex_buf), dex_name)
                        for i in range(len(dex.classes)):
                            classes.add(dex.classes[i].fullname)
        return classes

    old_classes = collect_classes(old_apk)
    new_classes = collect_classes(new_apk)

    if prefix:
        dot_prefix = prefix.replace(".", "/")
        l_prefix = f"L{dot_prefix}" if not dot_prefix.startswith("L") else dot_prefix
        old_classes = {c for c in old_classes if c.startswith(l_prefix)}
        new_classes = {c for c in new_classes if c.startswith(l_prefix)}

    added_classes = sorted(new_classes - old_classes)
    removed_classes = sorted(old_classes - new_classes)
    common_classes = sorted(old_classes & new_classes)

    result = {
        "old_apk": old_apk,
        "new_apk": new_apk,
        "summary": {
            "old_class_count": len(old_classes),
            "new_class_count": len(new_classes),
            "added_classes": len(added_classes),
            "removed_classes": len(removed_classes),
            "common_classes": len(common_classes),
        },
        "added_classes": [_dalvik_to_dot(c) for c in added_classes[:limit]],
        "removed_classes": [_dalvik_to_dot(c) for c in removed_classes[:limit]],
    }

    if level == 1:
        return result

    # --- Level 2: method diff per common class ---
    old_methods = _collect_all_methods(old_apk)
    new_methods = _collect_all_methods(new_apk)

    class_changes = []
    total_added_methods = 0
    total_removed_methods = 0
    total_modified_methods = 0

    for cls in common_classes:
        old_sigs = old_methods.get(cls, set())
        new_sigs = new_methods.get(cls, set())
        added = sorted(new_sigs - old_sigs)
        removed = sorted(old_sigs - new_sigs)
        if not added and not removed:
            continue
        total_added_methods += len(added)
        total_removed_methods += len(removed)
        class_changes.append({
            "class": _dalvik_to_dot(cls),
            "added_methods": added,
            "removed_methods": removed,
        })

    result["summary"]["added_methods"] = total_added_methods
    result["summary"]["removed_methods"] = total_removed_methods
    result["class_changes"] = class_changes[:limit]

    if level == 2:
        return result

    # --- Level 3: bytecode hash diff + smali diff ---
    def get_method_bytecode_hash(apk_path, dalvik_class, method_sig):
        handler = ApkHandler(apk_path)
        hit = handler.get_class_dex(dalvik_class)
        if hit is None:
            return None, None
        _, d_buf = hit
        dex = DEX.parse(memoryview(d_buf), "")
        clazz = dex.get_class(dalvik_class)
        if clazz is None:
            return None, None
        for m in clazz.methods:
            sig = _format_method_sig(m, dex)
            if sig == method_sig:
                bc = m.bytecode
                if not bc:
                    return hashlib.sha256(b"").hexdigest(), dex
                return hashlib.sha256(bytes(bc)).hexdigest(), dex
        return None, None

    def get_method_smali(apk_path, dalvik_class, method_name_target, method_sig):
        handler = ApkHandler(apk_path)
        hit = handler.get_class_dex(dalvik_class)
        if hit is None:
            return []
        _, d_buf = hit
        dex = DEX.parse(memoryview(d_buf), "")
        clazz = dex.get_class(dalvik_class)
        if clazz is None:
            return []
        for m in clazz.methods:
            sig = _format_method_sig(m, dex)
            if sig == method_sig:
                return render_smali(m.bytecode, dex)
        return []

    modified_methods_total = 0
    for change in class_changes:
        cls = None
        for c in common_classes:
            if _dalvik_to_dot(c) == change["class"]:
                cls = c
                break
        if cls is None:
            continue

        # Find methods present in both but potentially modified (not in added/removed)
        old_sigs = old_methods.get(cls, set())
        new_sigs = new_methods.get(cls, set())
        shared = old_sigs & new_sigs

        mods = []
        for sig in sorted(shared):
            old_hash, _ = get_method_bytecode_hash(old_apk, cls, sig)
            new_hash, _ = get_method_bytecode_hash(new_apk, cls, sig)
            if old_hash is None or new_hash is None:
                continue
            if old_hash == new_hash:
                continue

            method_name = sig.split("(")[0]
            old_smali = get_method_smali(old_apk, cls, method_name, sig)
            new_smali = get_method_smali(new_apk, cls, method_name, sig)
            diff_lines = list(difflib.unified_diff(
                old_smali, new_smali,
                fromfile=f"old/{method_name}",
                tofile=f"new/{method_name}",
                lineterm="",
            ))
            if diff_lines:
                mods.append({
                    "signature": sig,
                    "diff": "\n".join(diff_lines[:100]),
                })

        if mods:
            modified_methods_total += len(mods)
            change["modified_methods"] = mods

    result["summary"]["modified_methods"] = modified_methods_total
    return result


_COMMAND_HANDLERS = {
    "manifest": handle_manifest,
    "list_classes": handle_list_classes,
    "outline": handle_outline,
    "getclass": handle_getclass,
    "findrefs": handle_findrefs,
    "list_methods": handle_list_methods,
    "search_strings": handle_search_strings,
    "list_native_libs": handle_list_native_libs,
    "extract_dex": handle_extract_dex,
    "list_resources": handle_list_resources,
    "get_string_constants": handle_get_string_constants,
    "scan_secrets": handle_scan_secrets,
    "disassemble_method": handle_disassemble_method,
    "get_certificate": handle_get_certificate,
    "call_graph": handle_call_graph,
    "apk_diff": handle_apk_diff,
}


def main():
    if len(sys.argv) < 2:
        print(json.dumps({"status": "error", "error": "Missing command argument"}), file=sys.stdout)
        sys.exit(1)

    command = sys.argv[1]
    handler = _COMMAND_HANDLERS.get(command)
    if not handler:
        print(json.dumps({"status": "error", "error": f"Unknown command: {command}"}), file=sys.stdout)
        sys.exit(1)

    try:
        raw_input = sys.stdin.read()
        payload = json.loads(raw_input) if raw_input.strip() else {}
        result = handler(payload)
        print(json.dumps({"status": "ok", "data": result}, ensure_ascii=False), file=sys.stdout)
    except Exception as e:
        err_response = {
            "status": "error",
            "error": str(e),
            "traceback": traceback.format_exc(),
        }
        print(json.dumps(err_response, ensure_ascii=False), file=sys.stdout)
        sys.exit(1)


if __name__ == "__main__":
    main()
