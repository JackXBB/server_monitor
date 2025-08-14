#!/bin/bash
# install_server_monitoring.sh
# 自动化安装脚本
#   - 部署监控脚本
#   - 注册 crontab 定时任务
#   - 卸载功能（可选删除整个 SCRIPT_DIR 目录）


### 1. 变量设置
MONITOR_SCRIPT_NAME="server_monitoring.sh"
CONFIG_FILE_NAME="monitor.conf"

# 以当前脚本所在目录为基准目录（不依赖运行时 pwd）
INSTALL_BASE_DIR="$(cd -- "$(dirname -- "$0")" && pwd -P)"
CONFIG_FILE_PATH="$INSTALL_BASE_DIR/$CONFIG_FILE_NAME"

# 默认值（若 monitor.conf 未设置时使用）
DEFAULT_SCRIPT_DIR="$INSTALL_BASE_DIR/scripts"
DEFAULT_CRON_SCHEDULE="*/60 * * * *"   # 每60分钟

### ---- 读取配置（如果存在）----
if [[ -f "$CONFIG_FILE_PATH" ]]; then
  # shellcheck source=/dev/null
  source "$CONFIG_FILE_PATH"
  echo "🔧 已加载配置: $CONFIG_FILE_PATH"
else
  echo "⚠️ 未找到配置文件: $CONFIG_FILE_PATH，使用默认值"
fi

# 应用默认值（若配置中未提供）
: "${SCRIPT_DIR:="$DEFAULT_SCRIPT_DIR"}"
: "${CRON_SCHEDULE:="$DEFAULT_CRON_SCHEDULE"}"

# 若 SCRIPT_DIR 为相对路径，则转为绝对路径（基于 INSTALL_BASE_DIR）
if [[ "$SCRIPT_DIR" != /* ]]; then
  SCRIPT_DIR="$INSTALL_BASE_DIR/$SCRIPT_DIR"
fi

INSTALL=true  # 默认进行安装，如果需要卸载，设为 false
REMOVE_SCRIPT_DIR=false  # 默认不删除 SCRIPT_DIR 目录及其内容

### 2. 卸载功能判断
if [ "$1" == "uninstall" ]; then
    INSTALL=false    
    echo "🔴 正在卸载..."
    # 如果第二个参数是 `--remove-dir`，则标记删除 SCRIPT_DIR 目录
    if [ "$2" == "--remove-dir" ]; then
        REMOVE_SCRIPT_DIR=true
        echo "💡 将同时删除整个脚本目录及其内容：$SCRIPT_DIR"
    fi
fi

### 3. 安装：创建脚本目录并部署文件
if [ "$INSTALL" = true ]; then
    echo "📁 正在安装监控脚本..."

    # 创建脚本目录并复制监控脚本和配置文件
    mkdir -p "$SCRIPT_DIR"
    echo "📁 正在复制: $MONITOR_SCRIPT_NAME → $SCRIPT_DIR"
    cp "$MONITOR_SCRIPT_NAME" "$SCRIPT_DIR/"
    cp "$CONFIG_FILE_NAME" "$SCRIPT_DIR/"
    chmod +x "$SCRIPT_DIR/$MONITOR_SCRIPT_NAME"

    # 注册 crontab 定时任务
    if ! crontab -l 2>/dev/null | grep -q "$MONITOR_SCRIPT_NAME"; then
        echo "🕒 正在注册 crontab..."
        (crontab -l 2>/dev/null; echo "$CRON_SCHEDULE bash $SCRIPT_DIR/$MONITOR_SCRIPT_NAME") | crontab -
    else
        echo "✅ crontab 已经注册"
    fi
    # 安装完成后立即执行一次脚本
    echo "🚀 安装完成，正在立即执行一次监控脚本..."
    bash "$SCRIPT_DIR/$MONITOR_SCRIPT_NAME"
    ### 完成提示
    cat <<DONE
🎉 安装完成！
- 监控脚本路径: $SCRIPT_DIR/$MONITOR_SCRIPT_NAME
- 配置文件路径: $SCRIPT_DIR/$CONFIG_FILE_NAME
- 日志目录: $SCRIPT_DIR/log
- crontab 执行周期: $CRON_SCHEDULE
DONE

else
    ### 卸载：删除文件并取消 crontab 定时任务
    echo "📂 正在卸载监控脚本..."

    # 删除监控脚本和配置文件
    rm -f "$SCRIPT_DIR/$MONITOR_SCRIPT_NAME"
    rm -f "$SCRIPT_DIR/$CONFIG_FILE_NAME"

    # 移除 crontab 定时任务
    crontab -l 2>/dev/null | grep -v "$MONITOR_SCRIPT_NAME" | crontab -

    ### 如果选择删除整个脚本目录及其内容
    if [ "$REMOVE_SCRIPT_DIR" = true ]; then
        echo "🧹 正在删除整个脚本目录及其内容：$SCRIPT_DIR"
        rm -rf "$SCRIPT_DIR"
    fi
    ### 完成提示
    cat <<DONE
🎉 卸载完成！
- 监控脚本已删除: $SCRIPT_DIR/$MONITOR_SCRIPT_NAME
- 配置文件已删除: $SCRIPT_DIR/$CONFIG_FILE_NAME
- crontab 定时任务已移除
DONE
    if [ "$REMOVE_SCRIPT_DIR" = true ]; then
        echo "📁 整个脚本目录已删除：$SCRIPT_DIR"
    fi
fi

### 执行方法
# 安装时: $ sudo bash install_server_monitoring.sh
# 卸载时: $ sudo bash install_server_monitoring.sh uninstall
# 可选卸载 SCRIPT_DIR 目录: $ sudo bash install_server_monitoring.sh uninstall --remove-dir
#
### 功能说明
# 1. 安装时，脚本将 server_monitoring.sh 和 monitor.conf 文件复制到 $SCRIPT_DIR目录
# 2. 设置执行权限 (chmod +x)
# 3. 自动注册 crontab → 默认每 60 分钟执行一次
# 4. 卸载时，将删除脚本文件，并移除 crontab 中的定时任务
# 5. 可选卸载整个脚本目录及其内容，通过参数 `--remove-dir` 实现