#!/usr/bin/env bash
set -euo pipefail

# === 可按需修改 / 环境变量覆盖 ===
SERVICE_NAME="${SERVICE_NAME:-user-monitor}"
APP_FILE="${APP_FILE:-user_monitor.py}"
HOST_BIND="${HOST_BIND:-127.0.0.1}"   # 外网访问用 0.0.0.0
PORT="${PORT:-8000}"                  # 起始端口
PORT_TRY_MAX="${PORT_TRY_MAX:-200}"   # 最多尝试多少个端口

# === 自动探测 ===
USER_NAME="${USER:-$(id -un)}"
APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_PATH="$APP_DIR/$APP_FILE"
VENV_DIR="$APP_DIR/.venv"
PY_BIN="$VENV_DIR/bin/python"
SYSTEMD_USER_DIR="$HOME/.config/systemd/user"
SERVICE_FILE="$SYSTEMD_USER_DIR/${SERVICE_NAME}.service"

# --- 端口检测工具 ---
port_in_use() {
  local p="${1:-}"
  [[ -z "$p" ]] && return 1
  if command -v ss >/dev/null 2>&1; then
    ss -Hln "sport = :${p}" 2>/dev/null | grep -q .
    return $?
  elif command -v lsof >/dev/null 2>&1; then
    lsof -iTCP -sTCP:LISTEN -P -n 2>/dev/null | grep -E -q "[:.]${p}([[:space:]]|$)"
    return $?
  elif command -v nc >/dev/null 2>&1; then
    nc -z 127.0.0.1 "$p" >/dev/null 2>&1
    return $?
  fi
  return 1
}

find_free_port() {
  local start="${1:-}"
  if [[ -z "$start" ]]; then
    echo "find_free_port: missing start port" >&2
    return 2
  fi
  local candidate="$start"
  local tries=0
  while (( tries < PORT_TRY_MAX )); do
    if ! port_in_use "$candidate"; then
      printf '%s\n' "$candidate"
      return 0
    fi
    candidate=$((candidate + 1))
    tries=$((tries + 1))
  done
  return 1
}

print_url() {
  local host="${1:-$HOST_BIND}"
  local port="${2:-$PORT}"
  echo "----------------------------------------------------------------"
  echo "Web 页面地址：  http://${host}:${port}"
  if [[ "$host" == "127.0.0.1" || "$host" == "localhost" ]]; then
    echo "(注意：仅本机可访问。如需外部访问，设置 HOST_BIND=0.0.0.0)"
    echo "SSH 转发示例：ssh -L ${port}:127.0.0.1:${port} ${USER_NAME}@<服务器>"
  fi
  echo "----------------------------------------------------------------"
}

# --- 主要子命令 ---
cmd_install() {
  echo "==> 当前用户: ${USER_NAME}"
  echo "==> 程序路径: ${APP_PATH}"
  echo "==> 虚拟环境: ${VENV_DIR}"
  echo "==> systemd 用户单元: ${SERVICE_FILE}"

  if [[ ! -f "$APP_PATH" ]]; then
    echo "错误：找不到程序文件 $APP_PATH"
    exit 1
  fi

  # venv
  if [[ ! -x "$PY_BIN" ]]; then
    echo "==> 创建虚拟环境: $VENV_DIR"
    python3 -m venv "$VENV_DIR"
  else
    echo "==> 复用虚拟环境: $VENV_DIR"
  fi
  echo "==> 安装依赖（fastapi / uvicorn / psutil）..."
  "$PY_BIN" -m pip install --upgrade pip >/dev/null
  "$PY_BIN" -m pip install fastapi uvicorn psutil >/dev/null

  # 找可用端口
  chosen_port="$PORT"
  if p="$(find_free_port "$PORT")"; then
    chosen_port="$p"
    if [[ "$chosen_port" != "$PORT" ]]; then
      echo "==> 端口 ${PORT} 被占用，自动改用 ${chosen_port}"
    fi
  else
    echo "错误：从 ${PORT} 起连续 ${PORT_TRY_MAX} 个端口均不可用。"
    exit 2
  fi

  # 写 unit
  mkdir -p "$SYSTEMD_USER_DIR"
  cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Linux User Monitor Web Service
After=network.target

[Service]
Type=simple
ExecStart=${PY_BIN} ${APP_PATH}
WorkingDirectory=${APP_DIR}
Environment=PYTHONUNBUFFERED=1
Environment=HOST_BIND=${HOST_BIND}
Environment=PORT=${chosen_port}
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=default.target
EOF
  echo "==> 写入 service: $SERVICE_FILE"

  systemctl --user daemon-reload
  systemctl --user enable --now "${SERVICE_NAME}"

  echo "==> 服务已启动并设置为开机自启。"
  echo "   状态: systemctl --user status ${SERVICE_NAME}"
  echo "   日志: journalctl --user -u ${SERVICE_NAME} -f"
  print_url "$HOST_BIND" "$chosen_port"
}

cmd_start()    { systemctl --user start   "${SERVICE_NAME}"; echo "==> 已启动 ${SERVICE_NAME}"; }
cmd_stop()     { systemctl --user stop    "${SERVICE_NAME}"; echo "==> 已停止 ${SERVICE_NAME}"; }
cmd_restart()  { systemctl --user restart "${SERVICE_NAME}"; echo "==> 已重启 ${SERVICE_NAME}"; }
cmd_status()   { systemctl --user status  "${SERVICE_NAME}"; }
cmd_logs()     { journalctl --user -u "${SERVICE_NAME}" -f; }
cmd_enable()   { systemctl --user enable  "${SERVICE_NAME}"; echo "==> 已设置开机自启"; }
cmd_disable()  { systemctl --user disable "${SERVICE_NAME}"; echo "==> 已取消开机自启"; }
cmd_uninstall() {
  echo "==> 卸载 ${SERVICE_NAME} ..."
  systemctl --user stop "${SERVICE_NAME}" 2>/dev/null || true
  systemctl --user disable "${SERVICE_NAME}" 2>/dev/null || true
  rm -f "$SERVICE_FILE"
  systemctl --user daemon-reload
  echo "==> 已删除 ${SERVICE_FILE} 并取消自启。"
}

usage() {
  cat <<USAGE
用法: $0 [install|start|stop|restart|status|logs|enable|disable|uninstall]

  install     创建/更新 service 并启用+启动（默认）
  start       启动服务
  stop        停止服务
  restart     重启服务
  status      查看状态
  logs        实时查看日志
  enable      设置开机自启
  disable     取消开机自启
  uninstall   停止+禁用并删除 service 文件

环境变量可覆盖:
  HOST_BIND (默认 127.0.0.1)
  PORT      (默认 8000)
示例:
  HOST_BIND=0.0.0.0 PORT=9001 $0 install
USAGE
}

# === 入口 ===
subcmd="${1:-install}"
case "$subcmd" in
  install)   cmd_install ;;
  start)     cmd_start ;;
  stop)      cmd_stop ;;
  restart)   cmd_restart ;;
  status)    cmd_status ;;
  logs)      cmd_logs ;;
  enable)    cmd_enable ;;
  disable)   cmd_disable ;;
  uninstall) cmd_uninstall ;;
  -h|--help|help) usage ;;
  *) echo "未知子命令：$subcmd"; usage; exit 2 ;;
esac