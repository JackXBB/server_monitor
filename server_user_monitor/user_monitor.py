from __future__ import annotations
import uvicorn
import os
import json
import pwd
import shutil
import stat
import subprocess
import time
from pathlib import Path
from typing import List, Optional, Dict, Any, Iterator

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

try:
    import psutil
    NoSuchProcess = psutil.NoSuchProcess
except Exception:
    psutil = None
    class NoSuchProcess(Exception):
        pass

APP_TITLE = "Linux User Monitor"
app = FastAPI(title=APP_TITLE)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

CURRENT_USER = pwd.getpwuid(os.getuid()).pw_name
HOME = Path.home().resolve()
ALLOWED_BASE_DIRS: List[Path] = [HOME]
CONFIG_PATH = HOME / ".nonroot_monitor_config.json"

DEFAULT_CONFIG: Dict[str, Any] = {
    "allowed_base_dirs": [str(HOME)],
    "restart_registry": {}
}

if CONFIG_PATH.exists():
    try:
        user_cfg = json.loads(CONFIG_PATH.read_text())
        if isinstance(user_cfg, dict):
            DEFAULT_CONFIG.update(user_cfg)
    except Exception:
        pass

ALLOWED_BASE_DIRS = [Path(p).resolve() for p in DEFAULT_CONFIG.get("allowed_base_dirs", [str(HOME)])]
RESTART_REGISTRY: Dict[str, Dict[str, str]] = DEFAULT_CONFIG.get("restart_registry", {})


def within_allowed(path: Path) -> bool:
    try:
        rp = path.resolve()
    except Exception:
        return False
    return any(str(rp).startswith(str(base) + os.sep) or rp == base for base in ALLOWED_BASE_DIRS)


def owned_by_current_user(path: Path) -> bool:
    try:
        st = path.stat(follow_symlinks=False)
        return st.st_uid == os.getuid()
    except Exception:
        return False


def file_info(p: Path) -> Dict[str, Any]:
    try:
        st = p.lstat()
        mode = stat.filemode(st.st_mode)
        size = st.st_size
        owner = pwd.getpwuid(st.st_uid).pw_name
        return {
            "name": p.name,
            "path": str(p),
            "is_dir": p.is_dir(),
            "is_link": p.is_symlink(),
            "size": size,
            "mode": mode,
            "owner": owner,
        }
    except Exception as e:
        return {"name": p.name, "path": str(p), "error": str(e)}


def iter_files_recursive(base: Path) -> Iterator[Path]:
    """安全递归遍历普通文件（跳过符号链接、设备文件等）"""
    stack = [base]
    while stack:
        cur = stack.pop()
        try:
            with os.scandir(cur) as it:
                for entry in it:
                    try:
                        p = Path(entry.path)
                        if entry.is_symlink():
                            continue
                        if entry.is_dir(follow_symlinks=False):
                            stack.append(p)
                        else:
                            # 只处理常规文件
                            try:
                                st = p.lstat()
                                if stat.S_ISREG(st.st_mode):
                                    yield p
                            except Exception:
                                continue
                    except Exception:
                        continue
        except Exception:
            continue


def dir_size_bytes(base: Path) -> int:
    if not base.exists() or not base.is_dir():
        return 0
    total = 0
    for f in iter_files_recursive(base):
        try:
            total += f.lstat().st_size
        except Exception:
            continue
    return total


class DeleteRequest(BaseModel):
    path: str
    recursive: bool = False


class KillRequest(BaseModel):
    pid: int
    signal: str = "TERM"


class RestartRequest(BaseModel):
    name: str


class StopRequest(BaseModel):
    name: str


class DirInfoQuery(BaseModel):
    path: str


class DirCleanupRequest(BaseModel):
    path: str
    max_bytes: int
    threshold_bytes: int
    dry_run: bool = False  # 先看效果再执行


@app.get("/", response_class=HTMLResponse)
async def index():
    return HTMLResponse(INDEX_HTML_TEMPLATE.replace("{{APP_TITLE}}", APP_TITLE))


@app.get("/api/disk")
async def disk_usage(path: Optional[str] = Query(None)):
    mounts = []
    targets = set(ALLOWED_BASE_DIRS)
    dir_size = None
    if path:
        p = Path(path).expanduser()
        if within_allowed(p):
            targets.add(p if p.is_dir() else p.parent)
            try:
                # 计算当前目录总大小（递归文件大小）
                dir_size = dir_size_bytes(p if p.is_dir() else p.parent)
            except Exception:
                dir_size = None
    for t in targets:
        try:
            total, used, free = shutil.disk_usage(str(t))
            mounts.append({"target": str(t), "total": total, "used": used, "free": free})
        except Exception:
            continue
    return {"mounts": mounts, "dir_size": dir_size}


@app.get("/api/fs")
async def list_dir(path: Optional[str] = Query(None)):
    base = Path(path).expanduser().resolve() if path else HOME
    if not within_allowed(base):
        raise HTTPException(status_code=403, detail="Path not allowed")
    if not base.exists() or not base.is_dir():
        raise HTTPException(status_code=400, detail="Not a directory")
    try:
        items = sorted(
            [file_info(base / name) for name in os.listdir(base)],
            key=lambda x: (not x.get("is_dir", False), x.get("name", "")),
        )
        return {"path": str(base), "items": items}
    except PermissionError:
        raise HTTPException(status_code=403, detail="Permission denied")


@app.delete("/api/fs")
async def delete_path(req: DeleteRequest):
    p = Path(req.path).expanduser().resolve()
    if not within_allowed(p):
        raise HTTPException(status_code=403, detail="Path not allowed")
    if not p.exists():
        raise HTTPException(status_code=404, detail="Path not found")
    if not owned_by_current_user(p):
        raise HTTPException(status_code=403, detail="Not the owner of the file/directory")
    try:
        if p.is_dir():
            if req.recursive:
                shutil.rmtree(p)
            else:
                p.rmdir()
        else:
            p.unlink()
        return {"ok": True}
    except PermissionError:
        raise HTTPException(status_code=403, detail="Permission denied")
    except OSError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/dirinfo")
async def dir_info(req: DirInfoQuery):
    p = Path(req.path).expanduser().resolve()
    if not within_allowed(p):
        raise HTTPException(status_code=403, detail="Path not allowed")
    if not p.exists() or not p.is_dir():
        raise HTTPException(status_code=400, detail="Not a directory")
    try:
        size = dir_size_bytes(p)
        return {"path": str(p), "size": size}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/dir_cleanup")
async def dir_cleanup(req: DirCleanupRequest):
    base = Path(req.path).expanduser().resolve()
    if not within_allowed(base):
        raise HTTPException(status_code=403, detail="Path not allowed")
    if not base.exists() or not base.is_dir():
        raise HTTPException(status_code=400, detail="Not a directory")
    if not owned_by_current_user(base):
        # 目录本身所有者需为当前用户，避免误删
        raise HTTPException(status_code=403, detail="Directory not owned by current user")

    # 当前大小
    cur_size = dir_size_bytes(base)
    deleted = []
    deleted_bytes = 0

    if cur_size <= req.max_bytes:
        return {
            "ok": True,
            "current_size": cur_size,
            "deleted_files": deleted,
            "deleted_bytes": deleted_bytes,
            "note": "Below max_bytes, no cleanup necessary.",
        }

    # 收集文件（仅常规文件），按 mtime 从早到晚
    files = []
    for f in iter_files_recursive(base):
        try:
            st = f.lstat()
            files.append((f, st.st_mtime, st.st_size))
        except Exception:
            continue
    files.sort(key=lambda x: x[1])  # mtime 升序（最早的在前）

    target_after = req.threshold_bytes
    size_now = cur_size

    for f, mtime, fsize in files:
        if size_now <= target_after:
            break
        if not owned_by_current_user(f):
            continue
        if req.dry_run:
            # 只记录，不真正删除
            deleted.append({"path": str(f), "size": fsize, "mtime": int(mtime), "dry_run": True})
            size_now -= fsize
            deleted_bytes += fsize
        else:
            try:
                f.unlink()
                deleted.append({"path": str(f), "size": fsize, "mtime": int(mtime)})
                size_now -= fsize
                deleted_bytes += fsize
            except Exception:
                continue

    return {
        "ok": True,
        "before_size": cur_size,
        "after_size": size_now,
        "deleted_files": deleted,
        "deleted_bytes": deleted_bytes,
        "dry_run": req.dry_run,
    }


def _safe_str(x: Any) -> str:
    try:
        return str(x)
    except Exception:
        return ""


@app.get("/api/processes")
async def processes(
    q: Optional[str] = Query(None, description="关键字，匹配 name/cmdline（大小写不敏感）"),
    sort: str = Query("cpu", regex="^(cpu|mem|pid|name)$", description="排序字段：cpu|mem|pid|name"),
    desc: bool = Query(True, description="是否降序"),
    limit: int = Query(0, ge=0, le=10000, description="最大条数，0 表示不限制"),
):
    """
    列出当前用户的进程（支持查询/排序/限制条数）
    """
    procs: List[Dict[str, Any]] = []
    q_lc = q.lower() if q else None

    if psutil:
        for p in psutil.process_iter(attrs=["pid", "name", "username", "cmdline", "cpu_percent", "memory_percent"]):
            info = p.info
            if info.get("username") != CURRENT_USER:
                continue
            name = info.get("name") or ""
            cmdline_list = info.get("cmdline") or []
            cmdline = " ".join(cmdline_list)
            if q_lc and (q_lc not in name.lower()) and (q_lc not in cmdline.lower()):
                continue
            procs.append({
                "pid": info.get("pid"),
                "name": name,
                "cmdline": cmdline,
                "cpu": info.get("cpu_percent"),
                "mem": info.get("memory_percent"),
            })
    else:
        out = subprocess.check_output(["ps", "-u", CURRENT_USER, "-o", "pid=,comm=,args="], text=True)
        for line in out.strip().splitlines():
            try:
                pid_str, name, args = line.strip().split(maxsplit=2)
            except ValueError:
                continue
            if q_lc and (q_lc not in name.lower()) and (q_lc not in args.lower()):
                continue
            procs.append({"pid": int(pid_str), "name": name, "cmdline": args})

    # 排序
    key_map = {
        "cpu": lambda x: x.get("cpu") or 0,
        "mem": lambda x: x.get("mem") or 0,
        "pid": lambda x: x.get("pid") or 0,
        "name": lambda x: _safe_str(x.get("name")).lower(),
    }
    procs.sort(key=key_map.get(sort, key_map["cpu"]), reverse=bool(desc))

    total = len(procs)
    if limit and total > limit:
        procs = procs[:limit]

    return {"user": CURRENT_USER, "total": total, "returned": len(procs), "processes": procs}


@app.post("/api/processes/kill")
async def kill_process(req: KillRequest):
    pid = req.pid
    try:
        if psutil:
            p = psutil.Process(pid)
            if p.username() != CURRENT_USER:
                raise HTTPException(status_code=403, detail="Cannot kill processes not owned by current user")
            if req.signal.upper() == "KILL":
                p.kill()
            else:
                p.terminate()
            return {"ok": True}
        else:
            status = Path(f"/proc/{pid}")
            if not status.exists():
                raise HTTPException(status_code=404, detail="No such process")
            if status.stat().st_uid != os.getuid():
                raise HTTPException(status_code=403, detail="Cannot kill processes not owned by current user")
            os.kill(pid, 9 if req.signal.upper() == "KILL" else 15)
            return {"ok": True}
    except NoSuchProcess:
        raise HTTPException(status_code=404, detail="No such process")
    except PermissionError:
        raise HTTPException(status_code=403, detail="Permission denied")


def _parse_systemd_list_units(text: str) -> List[Dict[str, Any]]:
    """
    解析：systemctl --user list-units --type=service --all --no-legend --no-pager
    行格式（变量间空格不定）：<UNIT> <LOAD> <ACTIVE> <SUB> <DESCRIPTION...>
    """
    items: List[Dict[str, Any]] = []
    for line in text.strip().splitlines():
        parts = line.split()
        if not parts:
            continue
        unit = parts[0]
        load = parts[1] if len(parts) > 1 else "-"
        active = parts[2] if len(parts) > 2 else "-"
        sub = parts[3] if len(parts) > 3 else "-"
        desc = " ".join(parts[4:]) if len(parts) > 4 else unit
        items.append({"unit": unit, "load": load, "active": active, "sub": sub, "desc": desc})
    return items


def _parse_systemd_list_unit_files(text: str) -> Dict[str, Dict[str, Any]]:
    """
    解析：systemctl --user list-unit-files --type=service --no-legend --no-pager
    行格式：<UNIT> <STATE> [<VENDOR_PRESET>]
    返回 dict 以 unit 名字为 key
    """
    m: Dict[str, Dict[str, Any]] = {}
    for line in text.strip().splitlines():
        parts = line.split()
        if not parts:
            continue
        unit = parts[0]
        state = parts[1] if len(parts) > 1 else "-"
        vendor = parts[2] if len(parts) > 2 else "-"
        m[unit] = {"unit": unit, "file_state": state, "vendor_preset": vendor}
    return m


@app.get("/api/services")
async def user_services(
    q: Optional[str] = Query(None, description="关键字，匹配 unit/desc（大小写不敏感）"),
    state: str = Query("all", regex="^(all|running|failed|inactive)$", description="状态过滤"),
    limit: int = Query(0, ge=0, le=10000, description="最大条数，0 表示不限制"),
):
    """
    列出当前用户的 systemd --user 服务（包含 inactive），并合并 unit-files 中的未加载服务。
    支持按状态过滤与关键字查询。
    """
    services: List[Dict[str, Any]] = []
    extra_reason: Optional[str] = None

    q_lc = q.lower() if q else None

    try:
        out_units = subprocess.check_output(
            ["systemctl", "--user", "list-units", "--type=service", "--all", "--no-legend", "--no-pager"],
            text=True
        )
        units = _parse_systemd_list_units(out_units)
        services.extend(units)

        # 合并 unit-files，补充未加载但已安装的 unit
        try:
            out_files = subprocess.check_output(
                ["systemctl", "--user", "list-unit-files", "--type=service", "--no-legend", "--no-pager"],
                text=True
            )
            files_map = _parse_systemd_list_unit_files(out_files)
            present = {s["unit"] for s in services}
            for unit, meta in files_map.items():
                if unit not in present:
                    services.append({
                        "unit": unit,
                        "load": "-",
                        "active": "inactive",
                        "sub": "-",
                        "desc": f"(unit-file: {meta.get('file_state', '-')})",
                    })
        except Exception as e2:
            extra_reason = f"unit-files unavailable: {e2}"

    except Exception as e:
        # systemd --user 不可用，fallback 显示注册表
        extra_reason = f"systemd-user unavailable: {e}"
        for name in RESTART_REGISTRY.keys():
            services.append({"unit": name, "load": "-", "active": "unknown", "sub": "-", "desc": "(registry)"})

    # 关键字过滤
    if q_lc:
        services = [s for s in services if (q_lc in s["unit"].lower()) or (q_lc in _safe_str(s.get("desc")).lower())]

    # 状态过滤
    if state == "running":
        services = [s for s in services if s.get("active") == "active"]
    elif state == "failed":
        services = [s for s in services if s.get("active") == "failed"]
    elif state == "inactive":
        services = [s for s in services if s.get("active") == "inactive"]

    # 排个序：active 优先，其次按 unit 名
    def _sort_key(s: Dict[str, Any]):
        active_order = {"active": 0, "activating": 1, "reloading": 2, "inactive": 3, "failed": 4, "unknown": 5}
        return (active_order.get(s.get("active", "unknown"), 9), s.get("unit", ""))

    services.sort(key=_sort_key)

    total = len(services)
    if limit and total > limit:
        services = services[:limit]

    return {"user": CURRENT_USER, "total": total, "returned": len(services), "extra": extra_reason, "services": services}


@app.post("/api/services/restart")
async def restart_service(req: RestartRequest):
    name = req.name
    try:
        subprocess.check_call(["systemctl", "--user", "restart", name])
        return {"ok": True, "method": "systemd-user"}
    except Exception:
        pass
    reg = RESTART_REGISTRY.get(name)
    if not reg:
        raise HTTPException(status_code=400, detail="Service not found in user systemd nor restart registry")
    match = reg.get("match") or name
    start_cmd = reg.get("start")
    if not start_cmd:
        raise HTTPException(status_code=400, detail="Registry entry missing 'start' command")
    killed = 0
    if psutil:
        for p in psutil.process_iter(["pid", "username", "cmdline", "name"]):
            try:
                if p.info.get("username") != CURRENT_USER:
                    continue
                cmd = " ".join(p.info.get("cmdline") or []) or (p.info.get("name") or "")
                if match in cmd and p.pid != os.getpid():
                    p.terminate()
                    killed += 1
            except Exception:
                continue
    else:
        try:
            out = subprocess.check_output(["pgrep", "-f", match], text=True)
            for pid_s in out.strip().split():
                pid_i = int(pid_s)
                proc_path = Path(f"/proc/{pid_i}")
                if proc_path.exists() and proc_path.stat().st_uid == os.getuid():
                    try:
                        os.kill(pid_i, 15)
                        killed += 1
                    except Exception:
                        pass
        except subprocess.CalledProcessError:
            pass
    try:
        subprocess.Popen(start_cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return {"ok": True, "method": "registry", "killed": killed}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to start: {e}")


@app.post("/api/services/stop")
async def stop_service(req: StopRequest):
    """
    停止服务：
    - 优先使用 systemd --user stop
    - 否则使用注册表 match 终止相关进程（不启动）
    """
    name = req.name
    # 1) 尝试 systemd --user
    try:
        subprocess.check_call(["systemctl", "--user", "stop", name])
        return {"ok": True, "method": "systemd-user"}
    except Exception:
        pass

    # 2) fallback: 使用注册表匹配到的进程，全部终止
    reg = RESTART_REGISTRY.get(name)
    if not reg:
        # 如果没有注册表，尝试把 name 当作 match
        match = name
    else:
        match = reg.get("match") or name

    killed = 0
    if psutil:
        for p in psutil.process_iter(["pid", "username", "cmdline", "name"]):
            try:
                if p.info.get("username") != CURRENT_USER:
                    continue
                cmd = " ".join(p.info.get("cmdline") or []) or (p.info.get("name") or "")
                if match in cmd and p.pid != os.getpid():
                    p.terminate()
                    killed += 1
            except Exception:
                continue
    else:
        try:
            out = subprocess.check_output(["pgrep", "-f", match], text=True)
            for pid_s in out.strip().split():
                pid_i = int(pid_s)
                proc_path = Path(f"/proc/{pid_i}")
                if proc_path.exists() and proc_path.stat().st_uid == os.getuid():
                    try:
                        os.kill(pid_i, 15)
                        killed += 1
                    except Exception:
                        pass
        except subprocess.CalledProcessError:
            pass

    if killed == 0:
        raise HTTPException(status_code=400, detail="No processes matched; nothing stopped")
    return {"ok": True, "method": "match-kill", "killed": killed}


INDEX_HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang=zh>
<head>
  <meta charset=utf-8>
  <meta name=viewport content="width=device-width, initial-scale=1">
  <title>{{APP_TITLE}}</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-50 text-gray-800">
  <div class="max-w-[1200px] mx-auto p-4">
    <h1 class="text-2xl font-bold mb-3">{{APP_TITLE}}</h1>

    <!-- 顶部标签 -->
    <div class="flex gap-2 mb-3">
      <button id="tab-files" class="px-3 py-2 rounded-xl bg-blue-600 text-white">文件</button>
      <button id="tab-services" class="px-3 py-2 rounded-xl bg-gray-200">服务</button>
      <button id="tab-procs" class="px-3 py-2 rounded-xl bg-gray-200">进程</button>
      <div class="flex-1"></div>
      <label class="text-sm flex items-center gap-1 select-none">
        <input id="wrap-toggle" type="checkbox" class="align-middle"> 换行显示
      </label>
    </div>

    <!-- 面板：文件 -->
    <div id="panel-files" class="bg-white rounded-2xl shadow p-4">
      <div class="flex items-center gap-2 mb-2">
        <span class="font-semibold">文件浏览</span>
        <input id="path" class="flex-1 border rounded-lg px-3 py-2" placeholder="路径 (默认 $HOME)" />
        <button onclick="loadFS()" class="px-3 py-2 rounded-xl bg-blue-600 text-white">打开</button>
        <button onclick="goBack()" class="px-3 py-2 rounded-xl bg-gray-200">回退</button>
      </div>
      <div id="disk" class="mb-3 text-sm text-gray-600"></div>

      <div class="flex flex-wrap items-center gap-2 mb-3 text-sm">
        <span class="font-semibold">目录容量控制：</span>
        <label class="flex items-center gap-1">上限(GB)
          <input id="cfg-max" type="number" min="0" step="0.1" class="w-24 border rounded px-2 py-1" />
        </label>
        <label class="flex items-center gap-1">阈值(GB)
          <input id="cfg-threshold" type="number" min="0" step="0.1" class="w-24 border rounded px-2 py-1" />
        </label>
        <button onclick="savePolicy()" class="px-3 py-1 rounded bg-gray-100">保存</button>
        <button onclick="cleanup(false)" class="px-3 py-1 rounded bg-red-600 text-white">执行清理</button>
        <button onclick="cleanup(true)" class="px-3 py-1 rounded bg-yellow-500 text-white">试运行</button>
      </div>

      <div class="">
        <table class="min-w-full text-sm">
          <thead><tr class="text-left border-b"><th class="py-2">名称</th><th>类型</th><th>大小</th><th>权限</th><th>所有者</th><th class="text-right pr-2">操作</th></tr></thead>
          <tbody id="fs-body"></tbody>
        </table>
      </div>
    </div>

    <!-- 面板：服务 -->
    <div id="panel-services" class="hidden bg-white rounded-2xl shadow p-4">
      <div class="flex flex-wrap items-center justify-between gap-2 mb-2">
        <div class="font-semibold">服务（用户级）</div>
        <div class="flex flex-wrap items-center gap-2">
          <input id="svc-q" class="border rounded px-2 py-1 text-sm w-48" placeholder="搜索 unit/描述" />
          <select id="svc-state" class="border rounded px-2 py-1 text-sm">
            <option value="all">全部</option>
            <option value="running">运行中</option>
            <option value="inactive">已停止</option>
            <option value="failed">失败</option>
          </select>
          <select id="svc-page-size" class="border rounded px-2 py-1 text-sm">
            <option value="10">每页10</option>
            <option value="12" selected>每页12</option>
            <option value="20">每页20</option>
            <option value="50">每页50</option>
          </select>
          <button onclick="loadServices(true)" class="px-2 py-1 rounded-lg bg-gray-100">搜索</button>
        </div>
      </div>
      <div id="svc-meta" class="text-xs text-gray-500 mb-2"></div>
      <ul id="svc-list" class="space-y-1"></ul>
      <div class="flex items-center justify-between mt-3">
        <button id="svc-prev" class="px-3 py-1 rounded bg-gray-100">上一页</button>
        <div id="svc-pageinfo" class="text-sm text-gray-600"></div>
        <button id="svc-next" class="px-3 py-1 rounded bg-gray-100">下一页</button>
      </div>
    </div>

    <!-- 面板：进程 -->
    <div id="panel-procs" class="hidden bg-white rounded-2xl shadow p-4">
      <div class="flex flex-wrap items-center justify-between gap-2 mb-2">
        <div class="font-semibold">我的进程</div>
        <div class="flex items-center gap-2">
          <input id="proc-q" class="border rounded px-2 py-1 text-sm w-48" placeholder="搜索 name/cmdline" />
          <select id="proc-sort" class="border rounded px-2 py-1 text-sm">
            <option value="cpu">按CPU</option>
            <option value="mem">按内存</option>
            <option value="pid">按PID</option>
            <option value="name">按名称</option>
          </select>
          <select id="proc-page-size" class="border rounded px-2 py-1 text-sm">
            <option value="10">每页10</option>
            <option value="12" selected>每页12</option>
            <option value="20">每页20</option>
            <option value="50">每页50</option>
          </select>
          <button onclick="loadProcs(true)" class="px-2 py-1 rounded-lg bg-gray-100">搜索</button>
        </div>
      </div>
      <div id="proc-meta" class="text-xs text-gray-500 mb-2"></div>
      <ul id="proc-list" class="space-y-1"></ul>
      <div class="flex items-center justify-between mt-3">
        <button id="proc-prev" class="px-3 py-1 rounded bg-gray-100">上一页</button>
        <div id="proc-pageinfo" class="text-sm text-gray-600"></div>
        <button id="proc-next" class="px-3 py-1 rounded bg-gray-100">下一页</button>
      </div>
    </div>
  </div>

<script>
const navStack = [];
let lastServices = {list: [], total: 0, page: 1, pageSize: 12};
let lastProcs = {list: [], total: 0, page: 1, pageSize: 12};

function humanSize(bytes){
  const thresh = 1024;
  if (bytes === null || bytes === undefined) return '-';
  if (Math.abs(bytes) < thresh) return bytes + ' B';
  const units = ['KB','MB','GB','TB','PB'];
  let u = -1;
  do { bytes /= thresh; ++u; } while (Math.abs(bytes) >= thresh && u < units.length - 1);
  return bytes.toFixed(1)+' '+units[u];
}

function loadPolicy(path){
  const all = JSON.parse(localStorage.getItem('dirPolicies') || '{}');
  const p = all[path] || {};
  document.getElementById('cfg-max').value = p.max_gb ?? '';
  document.getElementById('cfg-threshold').value = p.threshold_gb ?? '';
}

function savePolicy(){
  const path = document.getElementById('path').value.trim() || '/';
  const max_gb = parseFloat(document.getElementById('cfg-max').value);
  const threshold_gb = parseFloat(document.getElementById('cfg-threshold').value);
  const all = JSON.parse(localStorage.getItem('dirPolicies') || '{}');
  all[path] = {max_gb, threshold_gb};
  localStorage.setItem('dirPolicies', JSON.stringify(all));
  alert('已保存目录策略');
  loadDisk(path);
}

async function loadDisk(path){
  const res = await fetch('/api/disk' + (path? ('?path='+encodeURIComponent(path)) : ''));
  const data = await res.json();
  const div = document.getElementById('disk');

  const all = JSON.parse(localStorage.getItem('dirPolicies') || '{}');
  const policy = all[path || ''] || {};
  const maxBytes = isFinite(policy.max_gb)? policy.max_gb * 1024**3 : null;
  const thresholdBytes = isFinite(policy.threshold_gb)? policy.threshold_gb * 1024**3 : null;

  const mountsHtml = (data.mounts||[]).map(m=>{
    const usedPct = (m.used*100.0/m.total).toFixed(1);
    return `
      <div class='mb-2'>
        <div class='flex justify-between'><span>${m.target}</span><span>${usedPct}%</span></div>
        <div class='w-full bg-gray-200 rounded h-2'><div class='h-2 rounded bg-blue-600' style='width:${usedPct}%'></div></div>
        <div class='text-xs text-gray-500'>已用 ${humanSize(m.used)} / 总计 ${humanSize(m.total)}</div>
      </div>
    `;
  }).join('');

  let dirHtml = '';
  if (path){
    const dsize = data.dir_size;
    let extra = '';
    if (maxBytes){
      const pct = Math.min(100, (dsize*100.0/maxBytes)).toFixed(1);
      extra = `
        <div class='w-full bg-gray-200 rounded h-2'><div class='h-2 rounded bg-green-600' style='width:${pct}%'></div></div>
        <div class='text-xs text-gray-500'>上限 ${humanSize(maxBytes)} · 阈值 ${thresholdBytes? humanSize(thresholdBytes):'-'}</div>
      `;
    }
    dirHtml = `
      <div class='mt-1 p-2 rounded border'>
        <div class='flex justify-between'><span>当前目录总大小</span><span>${humanSize(dsize)}</span></div>
        ${extra}
      </div>
    `;
  }

  div.innerHTML = mountsHtml + dirHtml;
}

async function cleanup(dryRun){
  const path = document.getElementById('path').value.trim();
  if(!path){ alert('请先选择目录'); return; }
  const all = JSON.parse(localStorage.getItem('dirPolicies') || '{}');
  const policy = all[path] || {};
  if(!isFinite(policy.max_gb) || !isFinite(policy.threshold_gb)){
    alert('请先填写并保存 上限/阈值');
    return;
  }
  const body = {
    path,
    max_bytes: policy.max_gb * 1024**3,
    threshold_bytes: policy.threshold_gb * 1024**3,
    dry_run: !!dryRun
  };
  const res = await fetch('/api/dir_cleanup', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body)});
  const data = await res.json();
  if(!res.ok){
    alert('清理失败: '+(data.detail||JSON.stringify(data)));
    return;
  }
  const total = data.deleted_files?.length || 0;
  alert((dryRun? '试运行结果：':'已清理：') + total + ' 个文件，释放 ' + humanSize(data.deleted_bytes||0));
  await loadDisk(path);
  await loadFS();
}

async function loadFS(){
  const path = document.getElementById('path').value.trim();
  await loadDisk(path);
  const res = await fetch('/api/fs' + (path? ('?path='+encodeURIComponent(path)) : ''));
  if(!res.ok){
    const t = await res.text();
    alert('无法读取目录: '+t);
    return;
  }
  const data = await res.json();
  const body = document.getElementById('fs-body');
  body.innerHTML = '';
  document.getElementById('path').value = data.path;
  loadPolicy(data.path);

  const up = data.path.split('/').slice(0,-1).join('/') || '/';
  body.innerHTML += `
    <tr class='border-b'>
      <td class='py-1'><a class='text-blue-600' href='#' onclick='nav("${up}", true)'>..</a></td>
      <td></td><td></td><td></td><td></td><td></td>
    </tr>`;

  (data.items||[]).forEach(it=>{
    const type = it.is_dir? '目录' : (it.is_link? '链接' : '文件');
    const sizeStr = (it.is_dir || !isFinite(it.size)) ? '-' : humanSize(it.size);
    const nameCell = it.is_dir
      ? `<a class='text-blue-600' title="${it.path}" href='#' onclick='nav("${it.path}")'>${it.name}</a>`
      : `<span title="${it.path}">${it.name}</span>`;
    const enterBtn = it.is_dir ? `<button class='px-2 py-1 rounded bg-gray-100' onclick='nav("${it.path}")'>进入</button>` : '';
    const row = `
      <tr class='border-b hover:bg-gray-50'>
        <td class='py-1'>${nameCell}</td>
        <td>${type}</td>
        <td>${sizeStr}</td>
        <td><code>${it.mode||''}</code></td>
        <td>${it.owner||''}</td>
        <td class='text-right pr-2'>
          ${enterBtn}
          <button class='px-2 py-1 rounded bg-red-600 text-white' onclick='delPath("${it.path}", ${it.is_dir})'>删除</button>
        </td>
      </tr>`;
    body.insertAdjacentHTML('beforeend', row);
  });
}

function nav(p, isUp=false){
  const cur = document.getElementById('path').value.trim();
  if(!isUp && cur) navStack.push(cur);
  document.getElementById('path').value = p;
  loadFS();
}
function goBack(){
  const last = navStack.pop();
  if(last){
    document.getElementById('path').value = last;
    loadFS();
  }
}
async function delPath(p, isDir){
  const recursive = isDir ? confirm('删除目录需要递归删除，确认继续?') : false;
  const res = await fetch('/api/fs', {method:'DELETE', headers:{'Content-Type':'application/json'}, body: JSON.stringify({path:p, recursive})});
  if(!res.ok){
    const t = await res.text();
    alert('删除失败: '+t);
  }
  await loadFS();
}

// ========== 带分页的 服务 & 进程 ==========

function isWrapOn(){ return document.getElementById('wrap-toggle')?.checked; }
function nameClasses(){ return isWrapOn() ? 'whitespace-normal break-all' : 'truncate'; }
function descClasses(){ return isWrapOn() ? 'whitespace-normal break-all text-xs text-gray-500' : 'text-xs text-gray-500 truncate'; }

function renderServicesPage(){
  const ul = document.getElementById('svc-list');
  ul.innerHTML = '';
  const page = lastServices.page;
  const size = lastServices.pageSize;
  const start = (page-1)*size;
  const end = Math.min(start+size, lastServices.list.length);
  const slice = lastServices.list.slice(start, end);

  slice.forEach(s=>{
    const unit = s.unit || '';
    const desc = s.desc || '';
    const li = `
      <li class='flex items-start justify-between gap-2 border rounded-lg px-2 py-1'>
        <div class='min-w-0 flex-1'>
          <div class='${nameClasses()}'>
            <span class='font-mono' title='${unit}'>${unit}</span>
            · <span class='text-xs ${s.active==='active' ? 'text-green-600':'text-gray-600'}'>
              ${s.active||''}/${s.sub||''}
            </span>
          </div>
          <div class='${descClasses()}' title='${desc}'>${desc}</div>
        </div>
        <div class='flex-shrink-0 flex gap-2'>
          <button class='px-2 py-1 rounded bg-blue-600 text-white' onclick='restartSvc("${unit}")'>重启</button>
          <button class='px-2 py-1 rounded bg-gray-500 text-white' onclick='stopSvc("${unit}")'>停止</button>
        </div>
      </li>`;
    ul.insertAdjacentHTML('beforeend', li);
  });

  const meta = document.getElementById('svc-meta');
  meta.textContent = `当前用户：${lastServices.user||'-'} · 共 ${lastServices.total} 条（本次查询匹配 ${lastServices.list.length} 条）`;

  const pageinfo = document.getElementById('svc-pageinfo');
  const pages = Math.max(1, Math.ceil(lastServices.list.length / size));
  pageinfo.textContent = `第 ${page} / ${pages} 页`;
  document.getElementById('svc-prev').disabled = page<=1;
  document.getElementById('svc-next').disabled = page>=pages;
}

function renderProcsPage(){
  const ul = document.getElementById('proc-list');
  ul.innerHTML = '';
  const page = lastProcs.page;
  const size = lastProcs.pageSize;
  const start = (page-1)*size;
  const end = Math.min(start+size, lastProcs.list.length);
  const slice = lastProcs.list.slice(start, end);

  slice.forEach(p=>{
    const cpu = (p.cpu && p.cpu.toFixed) ? (p.cpu.toFixed(1)+'% CPU') : '';
    const mem = (p.mem && p.mem.toFixed) ? (p.mem.toFixed(1)+'% MEM') : '';
    const cmd = p.cmdline || '';
    const li = `
      <li class='flex items-start justify-between gap-2 border rounded-lg px-2 py-1'>
        <div class='min-w-0 flex-1'>
          <div class='${nameClasses()}'>
            <span title="PID ${p.pid}">${p.pid}</span> · <span title="${p.name||''}">${p.name || ''}</span>
            <span class='text-xs text-gray-500'> ${cpu} ${mem}</span>
          </div>
          <div class='${descClasses()}' title="${cmd}">${cmd}</div>
        </div>
        <div class='flex-shrink-0 flex gap-2'>
          <button class='px-2 py-1 rounded bg-yellow-500 text-white' onclick='killProc(${p.pid}, "TERM")'>关闭</button>
          <button class='px-2 py-1 rounded bg-red-600 text-white' onclick='killProc(${p.pid}, "KILL")'>强制</button>
        </div>
      </li>`;
    ul.insertAdjacentHTML('beforeend', li);
  });

  const meta = document.getElementById('proc-meta');
  meta.textContent = `当前用户：${lastProcs.user||'-'} · 共 ${lastProcs.total} 条（本次查询匹配 ${lastProcs.list.length} 条）`;

  const pageinfo = document.getElementById('proc-pageinfo');
  const pages = Math.max(1, Math.ceil(lastProcs.list.length / size));
  pageinfo.textContent = `第 ${page} / ${pages} 页`;
  document.getElementById('proc-prev').disabled = page<=1;
  document.getElementById('proc-next').disabled = page>=pages;
}

async function loadServices(newQuery=false){
  // 读取筛选
  const q = document.getElementById('svc-q').value.trim();
  const state = document.getElementById('svc-state').value;

  // 请求（limit=0 取全量，客户端分页）
  const params = new URLSearchParams();
  if(q) params.set('q', q);
  if(state) params.set('state', state);
  params.set('limit', '0');

  const res = await fetch('/api/services?'+params.toString());
  const data = await res.json();

  lastServices.user = data.user;
  lastServices.total = data.total;
  lastServices.list = data.services || [];
  lastServices.pageSize = parseInt(document.getElementById('svc-page-size').value) || 12;
  if (newQuery) lastServices.page = 1;

  renderServicesPage();
}

async function loadProcs(newQuery=false){
  const q = document.getElementById('proc-q').value.trim();
  const sort = document.getElementById('proc-sort').value;

  const params = new URLSearchParams();
  if(q) params.set('q', q);
  if(sort) params.set('sort', sort);
  params.set('desc', 'true');
  params.set('limit', '0');

  const res = await fetch('/api/processes?'+params.toString());
  const data = await res.json();

  lastProcs.user = data.user;
  lastProcs.total = data.total;
  lastProcs.list = data.processes || [];
  lastProcs.pageSize = parseInt(document.getElementById('proc-page-size').value) || 12;
  if (newQuery) lastProcs.page = 1;

  renderProcsPage();
}

async function killProc(pid, sig){
  const res = await fetch('/api/processes/kill', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({pid, signal:sig})});
  if(!res.ok){
    const t = await res.text();
    alert('操作失败: '+t);
  }
  await loadProcs();
}

async function restartSvc(name){
  const res = await fetch('/api/services/restart', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({name})});
  if(!res.ok){
    const t = await res.text();
    alert('重启失败: '+t);
  } else {
    alert('已触发重启');
  }
  await loadServices();
}
async function stopSvc(name){
  const res = await fetch('/api/services/stop', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({name})});
  if(!res.ok){
    const t = await res.text();
    alert('停止失败: '+t);
  } else {
    alert('已触发停止');
  }
  await loadServices();
}

// 选项卡切换（不让页面滚动）
function showPanel(which){
  const pf = document.getElementById('panel-files');
  const ps = document.getElementById('panel-services');
  const pp = document.getElementById('panel-procs');
  pf.classList.toggle('hidden', which!=='files');
  ps.classList.toggle('hidden', which!=='services');
  pp.classList.toggle('hidden', which!=='procs');

  document.getElementById('tab-files').className = which==='files' ? 'px-3 py-2 rounded-xl bg-blue-600 text-white' : 'px-3 py-2 rounded-xl bg-gray-200';
  document.getElementById('tab-services').className = which==='services' ? 'px-3 py-2 rounded-xl bg-blue-600 text-white' : 'px-3 py-2 rounded-xl bg-gray-200';
  document.getElementById('tab-procs').className = which==='procs' ? 'px-3 py-2 rounded-xl bg-blue-600 text-white' : 'px-3 py-2 rounded-xl bg-gray-200';
}

// 初始绑定
function init(){
  // 选项卡
  document.getElementById('tab-files').onclick = ()=> showPanel('files');
  document.getElementById('tab-services').onclick = ()=> { showPanel('services'); loadServices(true); };
  document.getElementById('tab-procs').onclick = ()=> { showPanel('procs'); loadProcs(true); };

  // 分页按钮
  document.getElementById('svc-prev').onclick = ()=>{ if(lastServices.page>1){ lastServices.page--; renderServicesPage(); } };
  document.getElementById('svc-next').onclick = ()=>{ const pages=Math.max(1, Math.ceil(lastServices.list.length/lastServices.pageSize)); if(lastServices.page<pages){ lastServices.page++; renderServicesPage(); } };
  document.getElementById('proc-prev').onclick = ()=>{ if(lastProcs.page>1){ lastProcs.page--; renderProcsPage(); } };
  document.getElementById('proc-next').onclick = ()=>{ const pages=Math.max(1, Math.ceil(lastProcs.list.length/lastProcs.pageSize)); if(lastProcs.page<pages){ lastProcs.page++; renderProcsPage(); } };

  // 每页条数变更
  document.getElementById('svc-page-size').onchange = ()=>{ lastServices.pageSize=parseInt(document.getElementById('svc-page-size').value)||12; lastServices.page=1; renderServicesPage(); };
  document.getElementById('proc-page-size').onchange = ()=>{ lastProcs.pageSize=parseInt(document.getElementById('proc-page-size').value)||12; lastProcs.page=1; renderProcsPage(); };

  // 回车即搜索
  document.getElementById('svc-q').addEventListener('keydown', e=>{ if(e.key==='Enter') loadServices(true); });
  document.getElementById('proc-q').addEventListener('keydown', e=>{ if(e.key==='Enter') loadProcs(true); });

  // 换行开关影响渲染
  const wrapCtl = document.getElementById('wrap-toggle');
  if (wrapCtl) wrapCtl.addEventListener('change', ()=>{ renderServicesPage(); renderProcsPage(); });

  // 默认显示文件面板
  showPanel('files');
  // 预加载文件信息
  loadFS();
}
init();
</script>
</body>
</html>
"""


if __name__ == "__main__":
    host = os.getenv("HOST_BIND", "127.0.0.1")
    port = int(os.getenv("PORT", "8000"))
    uvicorn.run(app, host=host, port=port)
