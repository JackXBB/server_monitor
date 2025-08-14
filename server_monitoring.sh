#!/bin/bash
# server_monitoring.sh
# -------------------------------------------------------------------
# 服务器监控脚本 (2025.08)
# 周期性监控系统资源、网络、服务、Docker、进程、日志等，并向管理员发送警告邮件
#
# [系统概要]
#   - 将系统信息、uptime、CPU/内存使用率、磁盘、网络、登录用户等记录到日志。
#   - 服务器重启后若 uptime 小于 10 分钟则报警。
#
# [磁盘使用率检查]
#   - 检查各挂载点的使用率和 inode 使用率。
#   - 超过警告阈值(如 80%)和严重阈值(如 90%)时分别发送警告/严重告警。
#   - 记录大于 10GB 的大文件列表，便于删除无用文件。
#
# [Docker 卷监控]
#   - 如果已安装 Docker，检查各卷的使用情况并记录日志。
#
# [网络状态检查]
#   - 记录当前网络连接状态和统计信息。
#   - 如果已安装 ifstat，则测量带宽使用率。
#   - 对指定目标(IP)进行 ping 测试，失败则报警。
#   - DNS 解析测试失败则报警。
#
# [进程资源过高检查]
#   - 检查 CPU 或内存使用率超过阈值的进程。
#   - 如果该进程属于 Docker 容器：
#         * 如果容器名不包含关键字(如 db、prod)，则重启该容器。
#         * 如果是重要容器，则发送严重告警，提示人工检查。
#   - 如果是普通进程：
#         * 对于非关键进程(如 web 服务器、数据库等)，先发送 SIGTERM，若未结束则发送 SIGKILL 强制结束。
#
# [I/O 过高检测]
#   - 使用 iotop 记录 I/O 使用率高的进程。
#   - 若未安装 iotop，则发送 WARN 邮件。
#
# [服务状态检查]
#   - 检查指定服务是否正常运行。
#   - 服务宕机则尝试重启，重启失败则发送严重告警。
#   - 检查 Docker 容器状态，若有停止的容器则报警。
#
# [系统温度监控]
#   - 使用 lm-sensors 检查系统温度，若温度 ≥ 80°C，则发送警告邮件。
#
# [系统日志分析]
#   - 分析 journalctl 和 /var/log/auth.log，检查严重错误、
#     SSH 登录失败、OOM 事件等异常，并发送警告。
#
# [僵尸进程监控]
#   - 若僵尸进程数量 ≥ 10，则发送警告邮件。
#   - 记录僵尸进程及其父进程信息，向父进程发送 SIGCHLD 信号尝试回收。
#
# [文件监控和清理]
#   - 按文件夹总容量来判断是否需要清理，按日期排序文件，逐步清理文件直到释放足够的空间。
#   - 如果删除了文件，发送告警信息，告知哪些文件已被清理。
#
# [日志清理与汇总]
#   - 删除或压缩旧日志文件以释放空间。
#   - 每日将状态汇总发送邮件。
# -------------------------------------------------------------------

# 基本设置 - 脚本错误处理
export PATH=$PATH:/sbin:/usr/sbin
set -euo pipefail
IFS=$'\n\t'
# set -e: 命令执行失败时立即退出
# set -u: 使用未定义变量时报错
# set -o pipefail: 管道中任一命令失败则整体失败
# IFS: 单词分隔符限制为换行和制表符

# 检查是否为 root 权限
if [ "$EUID" -ne 0 ]; then
    echo "该脚本必须以 root 权限运行。"
    exit 1
fi

# [服务器标识符设置]
HOST_ID="$(hostname)"    #或： HOST_ID="server3", HOST_ID=$(hostname -I | awk '{print $1}')
#######################################################################
###################### [基本路径设置] ###################################
#######################################################################
# === 初始化全局变量 ===

# 读取配置文件
CONFIG_FILE="$(cd "$(dirname "$0")" && pwd)/monitor.conf"
if [ -f "$CONFIG_FILE" ]; then
    source "$CONFIG_FILE"
else
    echo "配置文件 $CONFIG_FILE 未找到，使用默认值"
fi

# 默认日志路径
LOG_BASE="${LOG_BASE:-$(cd "$(dirname "$0")" && pwd)/log}"  # 如果没有设置 LOG_BASE，使用默认的 ./log
LOG_ARCHIVE_DIR="${LOG_ARCHIVE_DIR:-$LOG_BASE/archive}"
LOG_ALERTS_DIR="${LOG_ALERTS_DIR:-$LOG_BASE/run_alerts}"

# 日志文件路径
GLOBAL_LOG="$LOG_BASE/global_$(date +%F).log"
RUN_ALERTS_FILE="${LOG_ALERTS_DIR}/run_alerts_$(date +%F_%H%M%S).log"


# 创建目录
mkdir -p "$LOG_BASE" "$LOG_ARCHIVE_DIR" "$LOG_ALERTS_DIR"
: > "$RUN_ALERTS_FILE"  # 初始化告警日志文件

#######################################################################
######################## [依赖检查] #####################################
#######################################################################

# 依赖检查结果记录的临时函数
log_dependency() {
    local msg="$1"  # 第 1 个参数 保存在局部变量 msg 里，记录的“日志内容”
    local level="$2"  # INFO, WARN, CRIT
    echo "[$(date '+%F %T')] [$level] $msg" >> "$GLOBAL_LOG"  #完整日志：[时间] [级别] 内容，写入文件 $GLOBAL_LOG
    echo "[$level] $msg"  # 同时输出到终端
}

# 检查必需命令
for cmd in "${REQUIRED_COMMANDS[@]}"; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        log_dependency "缺少必需命令 $cmd，无法继续执行。" "CRIT"
        exit 1
    fi
done
#sudo apt-get update && sudo apt-get install -y bc mailutils sysstat lm-sensors

# 检查可选命令
MISSING_COMMANDS=""
for cmd in "${OPTIONAL_COMMANDS[@]}"; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        log_dependency "未找到 $cmd 命令，部分功能可能受限。" "WARN"
        MISSING_COMMANDS="${MISSING_COMMANDS} $cmd"
    fi
done

# 是否启用服务器自愈功能 (默认关闭，风险较高)
ENABLE_SELF_HEALING=false

############################# [公共函数] ################################
# log(): 同时记录到函数日志文件和全局日志
log() {
    local msg="$1"
    local file="$2"
    local log_entry="[$(date '+%F %T')] $msg"
    echo -e "$log_entry" >> "$file"
    
    # WARN/CRIT 或标题行写入全局日志
    if echo "$msg" | grep -qE "\[(WARN|CRIT)\]|^(===|---)"; then
        echo -e "$log_entry" >> "$GLOBAL_LOG"
    fi
}

# run_cmd: 运行命令并在失败时记录日志和发送告警
# 用法: run_cmd "$LOG_FILE" <command>
run_cmd() {
    local LOG_FILE="$1"
    shift
    local cmd_name="$1"
    shift
    local resolved_cmd
    resolved_cmd=$(command -v "$cmd_name" 2>/dev/null || true)
    if [[ -z "$resolved_cmd" && -x "/sbin/$cmd_name" ]]; then
        resolved_cmd="/sbin/$cmd_name"
    elif [[ -z "$resolved_cmd" && -x "/usr/sbin/$cmd_name" ]]; then
        resolved_cmd="/usr/sbin/$cmd_name"
    fi

    if [[ -z "$resolved_cmd" ]]; then
        log "❌ Command not found: $cmd_name" "$LOG_FILE"
        send_alert "Command Not Found" "Command: $cmd_name" "ERROR" "run_cmd"
        return 127
    fi

    local timeout_secs=30
    local cmd_str="$resolved_cmd $(printf '%q ' "$@")"
    local output
    output=$(timeout "$timeout_secs" "$resolved_cmd" "$@" 2>&1)
    local exit_code=$?

    clean_output=$(echo "$output" | sed 's/\x1b\[[0-9;]*m//g')  # 去除ANSI颜色码
    echo -e ">>> CMD: $cmd_str\n$clean_output" >> "$LOG_FILE"

    if [ $exit_code -eq 1 ] && echo "$cmd_name" | grep -qE 'grep|egrep|fgrep'; then
        log "✅ No match found for command: $cmd_str (exit 1)" "$LOG_FILE"
        return 0
    fi
    if [ $exit_code -ne 0 ]; then
        log "❌ Command failed: $cmd_str (exit $exit_code)" "$LOG_FILE"
        send_alert "Command Failed" "Command: $cmd_str\nExit code: $exit_code\nOutput:\n$output" "WARN" "run_cmd"
    else
        log "✅ Command success: $cmd_str" "$LOG_FILE"
    fi
    return $exit_code
}

# safe_run: 安全执行函数并记录状态
# 用法: safe_run 函数名 或 safe_run my_func "$arg1" "$arg2"
safe_run() {
    local func_name="$1"
    shift
    local log_file="$GLOBAL_LOG"

    set +e
    "$func_name" "$@" 2>> "$log_file"
    local exit_code=$?
    set -e

    if [ $exit_code -ne 0 ]; then
        log "❌ $func_name failed (exit code: $exit_code)" "$log_file"
        send_alert "Function Failed" "Function $func_name failed with exit code $exit_code" "WARN" "$func_name"
    else
        log "→ $func_name completed successfully" "$log_file"
    fi
    return $exit_code
}

# 防止重复发送相同告警
should_send_alert() {
    local subject="${1:-}"
    local level="${2:-}"
    local message="${3:-}"
    local CACHE_FILE="$LOG_BASE/.alert_sent_cache"
    local now=$(date +%s)

    mkdir -p "$LOG_BASE"
    touch "$CACHE_FILE"

    local msg_hash
    msg_hash=$(echo "${message:-NO_MESSAGE}" | md5sum | awk '{print $1}')
    local cache_line=$(grep "^${subject}|" "$CACHE_FILE" || true)

    local interval
    case "$level" in
        "CRIT") interval=600 ;;   # 10 分钟
        "WARN") interval=1800 ;;  # 30 分钟
        "INFO") interval=3600 ;;  # 60 分钟
        *) interval=300 ;;        # 默认 5 分钟
    esac

    if [ -n "$cache_line" ]; then
        local last_time last_hash count
        last_time=$(echo "$cache_line" | cut -d'|' -f2)
        last_hash=$(echo "$cache_line" | cut -d'|' -f3)
        count=$(echo "$cache_line" | cut -d'|' -f4)
        count=${count:-1}

        if [ "$msg_hash" == "$last_hash" ]; then
            if (( now - last_time < interval )); then
                count=$((count + 1))
                sed -i "/^${subject}|/d" "$CACHE_FILE"
                echo "${subject}|${now}|${msg_hash}|${count}" >> "$CACHE_FILE"
                return 1
            fi
        fi
        sed -i "/^${subject}|/d" "$CACHE_FILE"
    fi

    echo "${subject}|${now}|${msg_hash}|1" >> "$CACHE_FILE"
    return 0
}

# send_alert() : 记录日志，并通过邮件发送通知
# - CRIT: 始终发送邮件
# - WARN: 当 SEND_WARN_EMAILS 为 true 时发送邮件
send_alert() {
    local subject="${1:-Unknown Alert}"
    local message="${2:-(no message)}"
    local level="${3:-INFO}"
    local context="${4:-}"  # 函数名或附加信息

    # 如果提供了 context，则添加到消息前
    if [ -n "$context" ]; then
        message="[$context]\n$message"
    fi
    
    local ALERT_CACHE_FILE="$LOG_BASE/.alert_sent_cache"

    # 所有通知记录到日志（包括 INFO）
    log "[${level}] ${subject}: ${message}" "$LOG_BASE/alerts_$(date +%F).log"
    echo "[$(date '+%F %T')] [${level}] ${subject}: ${message}" >> "$RUN_ALERTS_FILE"
    
    # INFO 不发送通知
    if [ "$level" = "INFO" ]; then
        return
    fi

    # 避免重复发送（5 分钟内相同 subject 不再发送）
    if ! should_send_alert "$subject" "$level"; then
        return
    fi
    
    local decorated_subject
    if [ "$level" == "CRIT" ]; then
        decorated_subject="-------- !!! [CRIT][$HOST_ID] Server Alert: $subject !!! --------"
    elif [ "$level" == "WARN" ]; then
        decorated_subject="-------- !! [WARN][$HOST_ID] Server Alert: $subject !! --------"
    else
        decorated_subject="[${level}][$HOST_ID] Server Alert: $subject"
    fi
    
    # 邮件发送：CRIT 始终发送，WARN 仅在 SEND_WARN_EMAILS 为 true 时发送
    if [ "$ENABLE_EMAIL_ALERTS" = true ] && \
    { [ "$level" = "CRIT" ] || { [ "$level" = "WARN" ] && [ "$SEND_WARN_EMAILS" = true ]; }; }; then
        # 支持多个邮箱地址（逗号分隔）
        IFS=',' read -ra RECIPIENTS <<< "$ALERT_EMAIL"
        for email in "${RECIPIENTS[@]}"; do
            if echo -e "$message" | mail -s "$decorated_subject" "$email"; then
                log "→ Email sent to $email (level: $level)" "$LOG_BASE/alerts_$(date +%F).log"
            else
                log "❌ Failed to send email to $email (level: $level)" "$LOG_BASE/alerts_$(date +%F).log"
            fi
        done
    fi
}

# 全局错误处理器：脚本中任何函数发生错误时，记录日志并发送通知
error_handler() {
    local exit_code=$?
    local line_no=${BASH_LINENO[0]}
    local err_msg="脚本在第 $line_no 行意外终止，退出码 $exit_code"
    echo "[$(date '+%F %T')] [CRIT] $err_msg" >> "$GLOBAL_LOG"
    
    if [ "$(type -t send_alert)" = "function" ]; then
        send_alert "Script Error" "$err_msg" "CRIT" "error_handler"
    else
        echo "[CRIT] $err_msg"
    fi
    exit $exit_code
}
trap error_handler ERR

########################## 系统摘要 #########################
# 记录系统基本信息、资源使用、网络状态等到日志
collect_system_summary() {
    local LOG_FILE="$LOG_BASE/system_summary_$(date +%F).log"
    log "====== 系统基本信息======" "$LOG_FILE"
    
    # 系统信息和 uptime
    log "--- 系统信息 ---" "$LOG_FILE"
    run_cmd "$LOG_FILE" uname -a >> "$LOG_FILE" || true
    run_cmd "$LOG_FILE" uptime >> "$LOG_FILE" || true
        
    # 检测重启：如果 uptime < 10 分钟，发 WARN 通知
    local uptime_min=$(awk '{print int($1 / 60)}' /proc/uptime)
    if [ "$uptime_min" -lt 10 ]; then
        send_alert "服务器刚刚重启" "Uptime 仅为 ${uptime_min} 分钟，请检查是否为预期重启。" "WARN" "collect_system_summary ($LOG_FILE)"
    fi
    
    # CPU 使用情况
    log "--- CPU 使用情况 ---" "$LOG_FILE"
    run_cmd "$LOG_FILE" top -bn1 | head -n 5 >> "$LOG_FILE" || true
    
    # 内存信息
    log "--- 内存信息 ---" "$LOG_FILE"
    run_cmd "$LOG_FILE" free -h >> "$LOG_FILE" || true
    
    # Swap 使用
    log "--- Swap 使用 ---" "$LOG_FILE"
    run_cmd "$LOG_FILE" swapon --show || true

    # 磁盘信息
    log "--- 磁盘使用 ---" "$LOG_FILE"
    run_cmd "$LOG_FILE" df -h >> "$LOG_FILE" || true
    
    # 网络信息
    log "--- 网络信息 ---" "$LOG_FILE"
    run_cmd "$LOG_FILE" ip -s addr >> "$LOG_FILE" || true
    
    # 登录用户
    log "--- 登录用户 ---" "$LOG_FILE"
    run_cmd "$LOG_FILE" w >> "$LOG_FILE" || true
}

##################### 磁盘使用检查 #########################
# 检查每个挂载点的磁盘和 inode 使用情况，超出阈值时发通知
check_disk_usage() {
    local LOG_FILE="$LOG_BASE/disk_usage_$(date +%F).log"
    log "====== 磁盘使用检查  ======" "$LOG_FILE"
    
    # 之前的磁盘使用记录
    local PREVIOUS_USAGE_FILE="$LOG_BASE/.prev_disk_usage"
    
    # 输出完整磁盘信息
    log "--- 磁盘信息 ---" "$LOG_FILE"
    df -h >> "$LOG_FILE"
    
    # 获取当前磁盘信息
    local current_disk_info
    current_disk_info=$(df -h | grep -vE '^Filesystem|tmpfs|udev')
    
    # 警告阈值检查
    local disk_warn_report
    disk_warn_report=$(echo "$current_disk_info" | awk -v threshold="$DISK_WARN" '{ if($5+0 >= threshold) print $0 }' | sort -k5nr)
    if [ -n "$disk_warn_report" ]; then
        send_alert "磁盘使用警告" "以下磁盘使用率超过 ${DISK_WARN}%：\n$disk_warn_report" "WARN" "check_disk_usage ($LOG_FILE)"
    fi
    
    # 严重阈值检查
    local disk_crit_report
    disk_crit_report=$(echo "$current_disk_info" | awk -v threshold="$DISK_CRIT" '{ if($5+0 >= threshold) print $0 }' | sort -k5nr)
    if [ -n "$disk_crit_report" ]; then
        send_alert "磁盘使用严重" "以下磁盘使用率超过 ${DISK_CRIT}%：\n$disk_crit_report" "CRIT" "check_disk_usage ($LOG_FILE)"
    fi
    
    # 与上一次的变化检测
    if [ -f "$PREVIOUS_USAGE_FILE" ]; then
        log "--- 磁盘使用变化 ---" "$LOG_FILE"
        ...
    else
        log "→ 没有历史磁盘使用数据用于对比" "$LOG_FILE"
    fi
    
    # 保存当前使用情况
    echo "$current_disk_info" | awk '{print $1, $3, $5, $6}' > "$PREVIOUS_USAGE_FILE"
    
    # inode 使用检查
    log "--- inode 使用 ---" "$LOG_FILE"
    df -i >> "$LOG_FILE"
    
    local inode_warn_report
    inode_warn_report=$(df -i | grep -vE '^Filesystem|tmpfs|udev' | awk -v threshold="$DISK_WARN" '{ if($5+0 >= threshold) print $0 }' | sort -k5nr)
    if [ -n "$inode_warn_report" ]; then
        send_alert "inode 使用警告" "高 inode 使用率 (>${DISK_WARN}%)：\n$inode_warn_report" "WARN" "check_disk_usage ($LOG_FILE)"
    fi
    
    local inode_crit_report
    inode_crit_report=$(df -i | grep -vE '^Filesystem|tmpfs|udev' | awk -v threshold="$DISK_CRIT" '{ if($5+0 >= threshold) print $0 }' | sort -k5nr)
    if [ -n "$inode_crit_report" ]; then
        send_alert "inode 使用严重" "严重 inode 使用率 (>${DISK_CRIT}%)：\n$inode_crit_report" "CRIT" "check_disk_usage ($LOG_FILE)"
    fi
    
    log "→ 磁盘使用检查完成" "$LOG_FILE"
}

################# Docker 卷监控 ############################
# 如果安装了 Docker，则检查每个 Docker 卷的使用情况
# 如果没有 Docker 命令，则发送 CRIT 通知
check_docker_volume_usage() {
    local LOG_FILE="$LOG_BASE/docker_volume_usage_$(date +%F).log"
    log "====== Docker 卷监控 ======" "$LOG_FILE"

    if command -v docker &>/dev/null; then
        run_cmd "$LOG_FILE" docker volume ls -q | while read volume; do
            local mountpoint usage
            mountpoint=$(run_cmd "$LOG_FILE" timeout 5s docker volume inspect "$volume" -f '{{ .Mountpoint }}')
            if [ -d "$mountpoint" ]; then
                usage=$(du -sh "$mountpoint" 2>/dev/null | awk '{print $1}')
                log "Volume: $volume ($mountpoint) → $usage" "$LOG_FILE"
            fi
        done || true
    else
        log "❌ 未找到 Docker 命令，跳过 Docker 卷监控。" "$LOG_FILE"
        send_alert "缺少 Docker" "未找到 Docker 命令，Docker 卷监控已禁用。" "WARN" "check_docker_volume_usage ($LOG_FILE)"
    fi
}


##################网络状态检查 ###############################
# 检查网络连接、带宽、Ping测试、DNS解析等，如有异常则发出警告
check_network_status() {
    local LOG_FILE="$LOG_BASE/net_status_$(date +%F).log"
    log "========= 网络状态检查  =========" "$LOG_FILE"

    # 当前连接状态
    log "--- Network Connections ---" "$LOG_FILE"
    run_cmd "$LOG_FILE" ss -tuna | head -20 >> "$LOG_FILE" || true
    
    # 连接状态统计
    log "--- Connection Statistics ---" "$LOG_FILE"
    run_cmd "$LOG_FILE" ss -s >> "$LOG_FILE" || true

    # 测量带宽使用量（如果已安装 ifstat）
    if command -v ifstat &> /dev/null; then
        log "--- Bandwidth Usage ---" "$LOG_FILE"
        # 自动检测主要接口
        local interfaces=$(ip -o link show | awk -F': ' '{print $2}' | grep -E '^(eth|ens|enp|eno|em|bond|wlan)')
        run_cmd "$LOG_FILE" ifstat -i $(echo "$interfaces" | tr '\n' ',') -b 1 1
    fi

    # Ping 测试
    log "--- Ping Tests ---" "$LOG_FILE"
    local ping_failures=0
    for target in "${PING_TARGETS[@]}"; do
        log "Pinging $target..." "$LOG_FILE"
        if ! run_cmd "$LOG_FILE" timeout 5s ping -c 3 -W 2 "$target" >> "$LOG_FILE" 2>&1; then
            ping_failures=$((ping_failures + 1))
            log "⚠️ Failed to ping $target" "$LOG_FILE"
        fi
    done
    
    if [ $ping_failures -gt 0 ]; then
        send_alert "Network Connectivity Issues" "Failed to ping $ping_failures out of ${#PING_TARGETS[@]} targets." "WARN" "check_network_status ($LOG_FILE)"
    fi

    # DNS 解析测试
    log "--- DNS Resolution Test ---" "$LOG_FILE"
    if ! run_cmd "$LOG_FILE" timeout 5s host -t A google.com >> "$LOG_FILE" 2>&1; then
        send_alert "DNS Resolution Failure" "Failed to resolve domain names. Check DNS configuration." "WARN" "check_network_status ($LOG_FILE)"
    fi

    # 连接状态分析
    log "--- Connection State Analysis ---" "$LOG_FILE"
    local established=$(ss -tan | grep ESTAB | wc -l) || true
    local time_wait=$(ss -tan | grep TIME-WAIT | wc -l) || true
    local close_wait=$(ss -tan | grep CLOSE-WAIT | wc -l) || true
    
    log "Established: $established, Time-Wait: $time_wait, Close-Wait: $close_wait" "$LOG_FILE"
    
    # CLOSE_WAIT 状态过多则可能存在 socket 泄漏风险
    if [ "$close_wait" -gt 100 ]; then
        send_alert "Socket Leak Warning" "Detected $close_wait CLOSE_WAIT connections. Possible socket leak in applications." "WARN" "check_network_status ($LOG_FILE)"
    fi
    
    # TIME_WAIT 状态非常多则建议检查内核参数
    if [ "$time_wait" -gt 1000 ]; then
        log "⚠️ High number of TIME_WAIT connections: $time_wait. Consider tuning tcp_tw_reuse and tcp_tw_recycle." "$LOG_FILE"
    fi
}

######################### 进程资源过高 ############################
# 检查 CPU 或内存使用率高的进程。
# - 如果属于 Docker 容器，且容器名称不包含关键字（如 db、prod 等），则尝试重启；
#   如果是重要容器，则发送 CRIT 级别警告。
# - 如果是普通进程，则先发送 SIGTERM，未结束则 SIGKILL 强制终止。
# 
# 使用 CONSECUTIVE_LIMIT 变量，只有相同进程连续 3 次超过阈值时才执行重启或终止操作
check_process_usage() {
    local LOG_FILE="$LOG_BASE/proc_usage_$(date +%F).log"
    log "====== 进程资源过高检查 ======" "$LOG_FILE"

    local TMP_FILE=$(mktemp /tmp/high_usage_pids.XXXXXX) # 使用 mktemp 生成唯一临时文件
    local CPU_COUNT=$(nproc)
    local CPU_THRESHOLD=$(echo "$CPU_COUNT * $CPU_WARN_PERCENT / 100" | bc | awk '{printf "%.0f", $1}')  # CPU 阈值：核心数 * 警告比例
    local MEM_TOTAL=$(free -m | awk '/^Mem:/{print $2}')
    local MEM_THRESHOLD=$((MEM_TOTAL * MEM_WARN_PERCENT / 100))  # 内存阈值：总内存的警告比例
    local CONSECUTIVE_LIMIT=3  # 连续检测次数（必须连续超限才执行操作）
    
    touch "$TMP_FILE"
    
    # 记录高 CPU/内存占用的进程
    log "--- High Resource Usage Processes ---" "$LOG_FILE"
    run_cmd "$LOG_FILE" ps -eo pid,ppid,user,pcpu,pmem,rss,cmd --sort=-%cpu | head -10 >> "$LOG_FILE" || true
    run_cmd "$LOG_FILE" ps -eo pid,ppid,user,pcpu,pmem,rss,cmd --sort=-%mem | head -10 >> "$LOG_FILE" || true
    
    # 防止管道错误中断执行
    set +e
    ps -eo pid,comm,pcpu,pmem,rss --sort=-%cpu | awk 'NR>1' | while read pid cmd cpu pmem rss; do
        local mem_mb=0
        if [[ "$rss" =~ ^[0-9]+$ ]]; then
            mem_mb=$(( rss / 1024 ))
        fi

        # 白名单：系统相关或管理脚本不自动处理
        if echo "$cmd" | grep -qiE "(systemd|sshd|init|monitoring)"; then
            continue
        fi

        # 同时超过 CPU 和内存阈值才处理（需要连续检测）
	    if [[ "$cpu" =~ ^[0-9.]+$ && "$mem_mb" =~ ^[0-9]+$ ]]; then
            if [ "$(echo "$cpu > $CPU_THRESHOLD" | bc -l)" -eq 1 ] && [ "$mem_mb" -gt "$MEM_THRESHOLD" ]; then
                local hit_count
                hit_count=$(grep -c "^$pid " "$TMP_FILE" 2>/dev/null || echo 0)
                if [ "$hit_count" -ge "$CONSECUTIVE_LIMIT" ]; then
                    local proc_owner proc_detail
                    proc_owner=$(ps -o user= -p "$pid")
                    proc_detail=$(ps -p "$pid" -o pid,ppid,user,cmd | tail -1)
                    
                    # 如果是重要服务（web、DB等），只报警不结束
                    if echo "$cmd" | grep -qiE "(httpd|nginx|mysql|postgres|mongo|redis|java|node|tomcat)"; then
                        send_alert "Critical Process High Load" "Critical process $pid ($cmd) by $proc_owner using CPU:${cpu}% MEM:${mem_mb}MB. Manual check required." "CRIT" "check_process_usage ($LOG_FILE)"
                    else
                        # 检查是否为 Docker 容器
                        local container_id
                        container_id=$(cat /proc/$pid/cgroup 2>/dev/null | grep "docker" | awk -F/ '{print $3}' | head -1)
                        if [ -n "$container_id" ]; then
                            local container_name
                            container_name=$(timeout 5s docker inspect --format '{{.Name}}' "$container_id" 2>/dev/null | sed 's/^\///')
                            log "→ Container $container_name ($container_id) has high resource usage processes" "$LOG_FILE"
                            docker stats --no-stream "$container_id" >> "$LOG_FILE" 2>&1 || true
                            if echo "$container_name" | grep -qiE "(db|database|data|main|prod|api)"; then
                                send_alert "Critical Container High Load" "Critical container $container_name has high resource usage. Manual check required." "CRIT" "check_process_usage($LOG_FILE)"
                            else
                                log "→ Restarting container $container_name" "$LOG_FILE"
                                docker restart "$container_id" >> "$LOG_FILE" 2>&1 || true
                                if [ $? -eq 0 ]; then
                                    send_alert "Container Restarted" "$container_name restarted due to high usage." "INFO" "check_process_usage ($LOG_FILE)"
                                else
                                    send_alert "Container Restart Failed" "Failed to restart $container_name" "CRIT" "check_process_usage ($LOG_FILE)"
                                fi
                            fi
                        else
                            # 普通进程：先 SIGTERM，再 SIGKILL
                            log "→ Sending SIGTERM to PID $pid" "$LOG_FILE"
                            run_cmd "$LOG_FILE" kill "$pid" >> "$LOG_FILE" 2>&1 || true
                            sleep 2
                            if run_cmd "$LOG_FILE" kill -0 "$pid" 2>/dev/null; then 
                                log "→ Process did not terminate, sending SIGKILL to PID $pid" "$LOG_FILE"
                                run_cmd "$LOG_FILE" kill -9 "$pid" >> "$LOG_FILE" 2>&1 || true
                                send_alert "Process Killed" "Killed process $pid ($cmd) due to high resource usage" "WARN" "check_process_usage ($LOG_FILE)"
                            fi
                        fi
                    fi
                    run_cmd "$LOG_FILE" sed -i "/^$pid /d" "$TMP_FILE" 2>/dev/null || true
                else
                    run_cmd "$LOG_FILE" echo "$pid $cmd $cpu $mem_mb" >> "$TMP_FILE" || true
                fi
            fi
        fi
    done
    set -e

    if [ -f "$TMP_FILE" ]; then
        local live_pids_file
        live_pids_file=$(mktemp)
        ps -eo pid | tail -n +2 > "$live_pids_file"
        grep -vFx -f "$live_pids_file" "$TMP_FILE" > "$TMP_FILE.cleaned" 2>/dev/null || true
        mv "$TMP_FILE.cleaned" "$TMP_FILE" 2>/dev/null || true
        rm -f "$live_pids_file"
    fi

    rm -f "$TMP_FILE"
}



########################I/O过载检测 ##################################
# 使用 iotop/pidstat 命令检查 I/O 使用量较高的进程
check_io_heavy_processes() {
    local LOG_FILE="$LOG_BASE/io_heavy_$(date +%F).log"
    log "====== I/O过载检测 ======" "$LOG_FILE"

    if command -v iotop &>/dev/null; then
        run_cmd "$LOG_FILE" timeout 10s iotop -b -n 3 -o >> "$LOG_FILE" 2>/dev/null || true
        
        # 简单检查是否有高 I/O 使用的进程（可选）
        local high_io_detected
        high_io_detected=$(grep -E "[0-9]+\.[0-9]+[ ]+[MKG]" "$LOG_FILE" | head -1)
        
        if [ -n "$high_io_detected" ]; then
            log "→ 检测到高 I/O 活动，请查看日志获取详情" "$LOG_FILE"
        else
            log "→ 未检测到显著的 I/O 活动" "$LOG_FILE"
        fi

    elif command -v pidstat &>/dev/null; then
        # 如果没有 iotop，则使用 pidstat 作为替代
        log "未找到 iotop，使用 pidstat 进行 I/O 监控..." "$LOG_FILE"

        local tmp_pidstat_log
        tmp_pidstat_log=$(mktemp /tmp/pidstat_output.XXXXXX)

        if timeout 10s pidstat -d 1 5 > "$tmp_pidstat_log" 2>&1; then
            awk 'NR > 7 { print }' "$tmp_pidstat_log" >> "$LOG_FILE"
            log "→ pidstat 输出已保存" "$LOG_FILE"
        else
            log "❌ pidstat 在 10 秒后失败或超时" "$LOG_FILE"
            send_alert "pidstat Timeout" "pidstat 命令执行失败或超时。" "WARN" "check_io_heavy_processes ($LOG_FILE)"
        fi

        rm -f "$tmp_pidstat_log"

    else
        # 如果两个命令都没有，使用其他方式检查 I/O 状态
        log "未找到 I/O 监控工具，使用替代方法..." "$LOG_FILE"
        
        # 1. 通过 /proc/diskstats 检查磁盘 I/O
        log "--- 磁盘 I/O 状态 ---" "$LOG_FILE"
        run_cmd "$LOG_FILE" cat /proc/diskstats | grep -E 'sd|nvme|vd' | awk '{print $3": "$6" reads, "$10" writes"}' >> "$LOG_FILE" || true
        
        # 2. 使用 top 命令查看 CPU 占用高的进程
        log "--- CPU 占用高的进程 ---" "$LOG_FILE"
        run_cmd "$LOG_FILE" top -b -n 1 -o %CPU | head -20 >> "$LOG_FILE" || true

        log "--- 进程状态 ---" "$LOG_FILE"
        run_cmd "$LOG_FILE" ps aux --sort=-pcpu | head -10 >> "$LOG_FILE" || true

        if command -v vmstat &>/dev/null; then
            local io_wait
            io_wait=$(vmstat 1 2 | tail -1 | awk '{print $16}')
            log "→ 系统 I/O 等待时间: $io_wait%" "$LOG_FILE"
            
            if [ "$io_wait" -gt 20 ]; then
                send_alert "High System I/O Wait" "系统 I/O 等待时间过高 ($io_wait%)，请检查磁盘性能。" "WARN" "check_io_heavy_processes ($LOG_FILE)"
            fi
        fi
    fi
    
    log "→ check_io_heavy_processes 完成" "$LOG_FILE"
}


################## 服务状态及容器检查 #########################
# 检查指定的服务是否正常运行
# 如果服务未运行，则尝试重启；若重启失败，则发送 CRIT 级别告警
# 同时检查 Docker 容器状态，如果存在已停止的容器，则发送 WARN 告警
check_services() {
    local LOG_FILE="$LOG_BASE/service_status_$(date +%F).log"
    log "====== 服务状态及容器检查  ======" "$LOG_FILE"
    
    for svc in "${SERVICES[@]}"; do
        # 先检查服务是否存在（不存在则跳过）
        if ! systemctl list-unit-files | grep -qw "$svc.service"; then
            log "→ 服务 $svc 未找到，跳过。" "$LOG_FILE"
            continue
        fi

        run_cmd "$LOG_FILE" systemctl is-active --quiet "$svc" || true
        local status=$?
        
        if [ $status -ne 0 ]; then
            # 如果服务未运行，则记录状态并尝试重启
            run_cmd "$LOG_FILE" systemctl status "$svc" --no-pager | head -15 >> "$LOG_FILE" || true
            send_alert "Service Down" "服务 $svc 未运行 (status: $status)" "CRIT" "check_services ($LOG_FILE)"
            
            # 尝试重启服务
            log "→ 尝试重启 $svc" "$LOG_FILE"
            run_cmd "$LOG_FILE" systemctl restart "$svc" >> "$LOG_FILE" 2>&1 || true
            sleep 2
            
            # 重启后再次检查状态
            run_cmd "$LOG_FILE" systemctl is-active --quiet "$svc" || true
            if [ $? -ne 0 ]; then
                send_alert "Service Restart Failed" "重启服务 $svc 失败" "CRIT" "check_services ($LOG_FILE)"
            else
                send_alert "Service Restarted" "服务 $svc 重启成功" "INFO" "check_services ($LOG_FILE)"
            fi
        else
            log "→ 服务 $svc 正常运行" "$LOG_FILE"
        fi
    done

    # 检查 Docker 容器状态（如果存在 docker 命令）
    if command -v docker &> /dev/null; then
        log "--- Docker 容器状态 ---" "$LOG_FILE"

        run_cmd "$LOG_FILE" timeout 5s docker ps -a >> "$LOG_FILE" || true
        local stopped_containers
        # 检查已停止的容器
        stopped_containers=$(run_cmd "$LOG_FILE" timeout 5s docker ps -f "status=exited" -q)
        if [ -n "$stopped_containers" ]; then
            log "→ 发现已停止的容器: $stopped_containers" "$LOG_FILE"
            send_alert "Stopped Containers" "部分 Docker 容器未运行" "INFO"  "check_services ($LOG_FILE)"
        fi
    fi
}

###################### 系统温度监控 ###########################
# 使用 lm-sensors 检查系统温度
# 如果温度超过 TEMP_THRESHOLD (80°C) 则发送 WARN 告警
check_system_temperature() {
    local LOG_FILE="$LOG_BASE/temp_status_$(date +%F).log"
    log "====== 系统温度监控======" "$LOG_FILE"

    if command -v sensors &>/dev/null; then
        run_cmd "$LOG_FILE" timeout 5s sensors >> "$LOG_FILE" 2>&1 || true
        # 如果温度超过设定阈值，则告警
        local high_temp
        high_temp=$(sensors | awk '/°C/ { if ($2+0 > '$TEMP_THRESHOLD') print $2 }')
        if [ -n "$high_temp" ]; then
            send_alert "High Temperature" "检测到系统温度过高: $high_temp，请检查散热系统。" "WARN" "check_system_temperature ($LOG_FILE)"
        fi
    else
        log "⚠️ 未找到 'sensors' 命令，请安装 lm-sensors 以进行温度监控。" "$LOG_FILE"
        send_alert "Missing Temperature Monitoring" "未安装 lm-sensors，请使用 'apt-get install lm-sensors' 安装以启用温度监控。" "WARN" "check_system_temperature ($LOG_FILE)"
    fi
}


######################系统日志分析 ##################################
# 使用 journalctl 和 /var/log/auth.log 分析严重系统事件及安全问题
# 检查 OOM, SSH 登录失败等
# 如果发现问题，则发送 WARN 或 CRIT 告警
analyze_system_logs() {
    local LOG_FILE="$LOG_BASE/sys_events_$(date +%F).log"
    log "====== 系统日志分析======" "$LOG_FILE"

    local KEYWORDS="watchdog|kernel|panic|oom|fail|error|usb|network|segfault|NMI|denied|violation|attack|suspicious"
           
    # 系统日志分析
    run_cmd "$LOG_FILE" journalctl -p 0..3 -n 1000 --since "1 hour ago" | grep -Ei "$KEYWORDS" >> "$LOG_FILE" || true
    
    # 认证日志分析（登录失败及安全事件）
    log "--- 认证日志分析 ---" "$LOG_FILE"
    run_cmd "$LOG_FILE" grep -i "fail\|invalid\|error\|denied" /var/log/auth.log 2>/dev/null | tail -50 >> "$LOG_FILE" || true
    local ssh_failures
    
    # 统计最近 3 小时的 SSH 登录失败次数
    ssh_failures=0
    ssh_failures=$(journalctl -u sshd --since "3 hour ago" | grep -c "Failed password") || true
    if [ "$ssh_failures" -gt 10 ]; then
        send_alert "SSH Brute Force" "最近 1 小时内检测到 $ssh_failures 次 SSH 登录失败，可能存在暴力破解攻击。" "WARN" "analyze_system_logs ($LOG_FILE)"
    fi

    # 检查 OOM Killer 事件
    if grep -q "Out of memory" "$LOG_FILE"; then
        send_alert "OOM Killer" "系统触发了 Out of Memory killer，需要立即处理。" "CRIT" "analyze_system_logs ($LOG_FILE)"
    fi
}

##################  僵尸进程监控 ###########################
# 僵尸进程数
# - 超过 WARN 阈值时：发送告警 + 记录日志
# - 超过 KILL 阈值时：向父进程发送 SIGCHLD 信号 + 针对每个容器重启
# - 记录僵尸进程及其父进程的详细信息，
# - 向父进程发送 SIGCHLD 信号尝试清理僵尸进程，并发送 WARN 告警。
manage_zombie_processes() {
    get_docker_container_name_by_pid() {
        local pid="$1"
        local cid=""
        local cname=""

        # 提取 Docker 容器 ID
        cid=$(cat /proc/"$pid"/cgroup 2>/dev/null | grep 'docker' | head -1 | awk -F/ '{print $3}')
        if [ -n "$cid" ]; then
            # 查询容器名称
            cname=$(docker ps --no-trunc --format '{{.ID}} {{.Names}}' | grep "$cid" | awk '{print $2}')
            echo "$cname"
        else
            echo ""
        fi
    }

    local LOG_FILE="$LOG_BASE/zombie_proc_$(date +%F).log"
    log "====== 僵尸进程监控 ======" "$LOG_FILE"

    # 检查僵尸进程数量
    local zombie_count=0
    zombie_count=$(ps -eo stat | grep -c '^Z') || true
    log "→ 发现 $zombie_count 个僵尸进程" "$LOG_FILE"

    declare -A container_zombie_count
    declare -A container_ppids

    if [ "$zombie_count" -ge "$ZOMBIE_WARN_THRESHOLD" ]; then
        local zombie_summary=""
        ps -eo pid,ppid,stat,cmd | awk '$3 ~ /Z/' | while read pid ppid stat cmd; do
            local cname
            cname=$(get_docker_container_name_by_pid "$ppid")
            if [ -n "$cname" ]; then
                if [ -z "${container_zombie_count[$cname]}" ]; then
                    container_zombie_count["$cname"]=1
                else
                    container_zombie_count["$cname"]=$((container_zombie_count["$cname"] + 1))
                fi

                container_ppids["$cname"]+="$ppid "
                log "→ 僵尸进程 PID $pid (父进程: $ppid, 容器: $cname)" "$LOG_FILE"
                zombie_summary+="僵尸进程 PID $pid (父进程: $ppid, 容器: $cname)\n"
            else
                log "→ 僵尸进程 PID $pid (父进程: $ppid, 无容器)" "$LOG_FILE"
                zombie_summary+="僵尸进程 PID $pid (父进程: $ppid, 无容器)\n"
            fi
        done

        send_alert "Zombie Processes" "僵尸进程数量过多: $zombie_count\n$zombie_summary" "WARN" "manage_zombie_processes ($LOG_FILE)"
    fi

    if [ "$zombie_count" -ge "$ZOMBIE_KILL_THRESHOLD" ]; then
        log "→ 僵尸进程数量超过清理阈值 ($ZOMBIE_KILL_THRESHOLD)，开始清理" "$LOG_FILE"
        
        # 发送 SIGCHLD 尝试清理
        for ppid in $(ps -eo ppid,stat | awk '$2=="Z" {print $1}' | sort | uniq); do
            run_cmd "$LOG_FILE" ps -p "$ppid" -o cmd= | grep -qE "(systemd|init|sshd)" && continue
            log "→ 向僵尸进程父进程 PID $ppid 发送 SIGCHLD" "$LOG_FILE"
            run_cmd "$LOG_FILE" kill -SIGCHLD "$ppid"
        done

        # 针对僵尸数量多的容器重启
        for cname in "${!container_zombie_count[@]}"; do
            local count=${container_zombie_count["$cname"]}
            if [ "$count" -ge "$ZOMBIE_KILL_THRESHOLD" ]; then
                log "→ 检查容器 $cname 的重启策略" "$LOG_FILE"
                # local restart_policy=$(docker inspect --format '{{.HostConfig.RestartPolicy.Name}}' "$cname" 2>/dev/null)
                local restart_policy=$(timeout 5s docker inspect --format '{{.HostConfig.RestartPolicy.Name}}' "$cname" 2>/dev/null || echo "")
                timeout 10s docker restart "$cname" >> "$LOG_FILE" 2>&1 && send_alert "Zombie Cleanup" "因 $count 个僵尸进程重启容器 $cname" "INFO" "manage_zombie_processes ($LOG_FILE)"
                log "→ $cname 的重启策略: $restart_policy" "$LOG_FILE"

                if [ "$restart_policy" = "" ] || [ "$restart_policy" = "no" ]; then
                    log "→ 警告: 容器 $cname 没有自动重启策略！" "$LOG_FILE"
                    send_alert "Container Restart Policy" "容器 $cname 无重启策略，但因僵尸进程溢出被重启。" "WARN" "manage_zombie_processes ($LOG_FILE)"
                fi

                log "→ 重启容器 $cname (僵尸数量: $count)" "$LOG_FILE"
                docker restart "$cname" >> "$LOG_FILE" 2>&1 && \
                    send_alert "Zombie Cleanup" "因 $count 个僵尸进程重启容器 $cname" "INFO" "manage_zombie_processes ($LOG_FILE)"
            fi
        done
    fi
}


###############服务器自愈脚本 ####################################
# 仅当 ENABLE_SELF_HEALING 设置为 true 时执行自动恢复功能。
# 尝试清理临时文件、重启失败服务、清理崩溃转储和会话等。
server_self_healing() {
    if [ "$ENABLE_SELF_HEALING" != true ]; then
        return
    fi
    local LOG_FILE="$LOG_BASE/self_healing_$(date +%F).log"
    log "====== 服务恢复 ======" "$LOG_FILE"
    
    # 清理旧临时文件
    log "--- 清理临时文件 ---" "$LOG_FILE"
    run_cmd "$LOG_FILE" find /tmp -type f -atime +7 -delete 2>/dev/null || true
    
    # 重启失败的 systemd 服务
    log "--- 恢复失败服务 ---" "$LOG_FILE"
    for failed_unit in $(systemctl --failed --plain --no-legend | awk '{print $1}'); do
        # 排除重要服务
        if echo "$failed_unit" | grep -qE "(network|sshd|firewalld)"; then
            log "→ 重要服务 $failed_unit 需人工检查" "$LOG_FILE"
            send_alert "关键服务失败" "关键服务 $failed_unit 失败，需要人工干预" "CRIT" "server_self_healing ($LOG_FILE)"
            continue
        fi
        
        log "→ 尝试重启失败服务 $failed_unit" "$LOG_FILE"
        run_cmd "$LOG_FILE" timeout 5s systemctl restart "$failed_unit"

        # 检查重启是否成功
        if systemctl is-active --quiet "$failed_unit"; then
            log "✅ 服务 $failed_unit 恢复成功" "$LOG_FILE"
            send_alert "服务恢复" "成功恢复失败服务: $failed_unit" "INFO" "server_self_healing ($LOG_FILE)"
        else
            log "❌ 服务 $failed_unit 恢复失败" "$LOG_FILE"
            send_alert "服务恢复失败" "无法恢复服务: $failed_unit" "WARN" "server_self_healing ($LOG_FILE)"
        fi
    done
    
    # 清理旧崩溃转储
    if [ -d "/var/crash" ]; then
        log "--- 清理崩溃转储 ---" "$LOG_FILE"
        run_cmd "$LOG_FILE" find /var/crash -type f -mtime +7 -delete 2>/dev/null || true
    fi
    
    # 清理僵尸会话
    log "--- 清理僵尸会话 ---" "$LOG_FILE"
    for zombie_session in $(loginctl list-sessions --no-legend | awk '$1 !~ /^[0-9]+$/ {print $1}'); do
        log "→ 移除僵尸会话 $zombie_session" "$LOG_FILE"
        run_cmd "$LOG_FILE" loginctl terminate-session "$zombie_session" >> "$LOG_FILE" 2>&1 || true
    done
    
    # 设置文件系统检查 (超过挂载次数时检查)
    log "--- 设置文件系统检查 ---" "$LOG_FILE"
    run_cmd "$LOG_FILE" tune2fs -l $(findmnt -no SOURCE / 2>/dev/null) 2>/dev/null | grep -E '挂载次数|最大挂载' >> "$LOG_FILE" || true
}

####################### Docker 容器日志分析 ################################
# 分析 Docker 容器日志，检查最近的错误、警告和重启次数等。
# 当检测到一定错误频率或重启次数时，发送 WARN 告警。
analyze_container_logs() {
    local LOG_FILE="$LOG_BASE/container_logs_$(date +%F).log"
    log "====== Docker 容器日志分析======" "$LOG_FILE"

    local RESTART_TRACK_FILE="$LOG_BASE/.container_restart_count"
    local ERROR_TRACK_FILE="$LOG_BASE/.container_error_count"
    touch "$RESTART_TRACK_FILE" "$ERROR_TRACK_FILE"

    if command -v docker &>/dev/null; then
        # 获取运行中的容器列表
        docker ps --format "{{.Names}}" | while read container; do
            log "-- 容器日志分析: $container ------" "$LOG_FILE"
            
            # 抽取错误和警告日志（包括超时强制终止 + 允许失败）
            if ! timeout --signal=SIGKILL 30s docker logs --tail 100 "$container" 2>&1 | \
               grep -iE "error|warn|exception|fail|fatal" | tail -10 >> "$LOG_FILE"; then
                log "⚠️ 获取 $container 日志 (tail 100) 超时或出错" "$LOG_FILE"
            fi

            # 检查错误频率（tail 1000）
            local error_count
            error_count=$(timeout --signal=SIGKILL 10s docker logs --tail 1000 "$container" 2>&1 | \
                grep -icE "error|exception|fatal" 2>/dev/null)
            error_count=${error_count:-0}

            # 读取之前错误数并计算增量
            local prev_error_count error_delta
            prev_error_count=$(grep "^$container:" "$ERROR_TRACK_FILE" | cut -d: -f2)
            prev_error_count=${prev_error_count:-0}
            error_delta=$((error_count - prev_error_count))

            grep -v "^$container:" "$ERROR_TRACK_FILE" > "${ERROR_TRACK_FILE}.tmp"
            echo "$container:$error_count" >> "${ERROR_TRACK_FILE}.tmp"
            mv "${ERROR_TRACK_FILE}.tmp" "$ERROR_TRACK_FILE"

            # 只在最近 1000 行日志错误数较之前增加 50 以上时发送告警
            if [[ "$error_delta" -ge 50 ]]; then
                send_alert "Container Error Spike" \
                    "容器 $container 的错误数量增加 $error_delta (从 $prev_error_count 增加到 $error_count)" \
                    "WARN" "analyze_container_logs ($LOG_FILE)"
            fi

            # 检查重启次数并检测变化
            local restart_count prev_count delta
            restart_count=$(docker inspect "$container" --format '{{.RestartCount}}' 2>/dev/null)
            restart_count=${restart_count:-0}
            prev_count=$(grep "^$container:" "$RESTART_TRACK_FILE" | cut -d: -f2)
            prev_count=${prev_count:-0}
            delta=$((restart_count - prev_count))

            # 更新记录
            grep -v "^$container:" "$RESTART_TRACK_FILE" > "${RESTART_TRACK_FILE}.tmp"
            echo "$container:$restart_count" >> "${RESTART_TRACK_FILE}.tmp"
            mv "${RESTART_TRACK_FILE}.tmp" "$RESTART_TRACK_FILE"

            # 条件：仅当重启次数较之前增加 50 以上时发送告警（忽略瞬时频繁重启）
            if [ "$delta" -ge 50 ]; then
                send_alert "Container Restart Increased" \
                    "容器 $container 重启次数增加 $delta (从 $prev_count 增加到 $restart_count)" \
                    "WARN" "analyze_container_logs ($LOG_FILE)"
            fi
        done
    else
        log "❌ 未找到 Docker 命令，跳过容器日志分析。" "$LOG_FILE"
    fi
}

#######################历史命令备份############################
backup_bash_history() {
    local LOG_FILE="$LOG_BASE/history_backup_$(date +%F).log"
    log "====== 历史命令备份 ======" "$LOG_FILE"

    local now_ts
    now_ts=$(date '+%F_%H%M%S')

    local users=("root")

    # 查找基本用户：根据 /home 下的目录
    for home_dir in /home/*; do
        [ -d "$home_dir" ] || continue
        user_name=$(basename "$home_dir")
        users+=("$user_name")
    done

    for u in "${users[@]}"; do
        local home_dir
        [ "$u" == "root" ] && home_dir="/root" || home_dir="/home/$u"

        local hist_file="$home_dir/.bash_history"
        local backup_file="$home_dir/.bash_history.bak.$now_ts"

        if [ -f "$hist_file" ]; then
            cp "$hist_file" "$backup_file" 2>> "$LOG_FILE" && \
            log "→ 备份 $hist_file 到 $backup_file" "$LOG_FILE"
        else
            log "⚠️ 未找到历史命令文件: $hist_file" "$LOG_FILE"
        fi
    done
}




####################### SSH 会话异常检测 ###############################
# 监控 SSH 连接稳定性（关注断开连接、会话、配置问题等）
monitor_ssh_stability() {
    local LOG_FILE="$LOG_BASE/ssh_stability_$(date +%F).log"
    log "====== SSH 会话异常检测 ======" "$LOG_FILE"

    ## [1] SSH 断开次数（最近1小时）
    local disconnects=0
    if command -v journalctl &>/dev/null; then
        disconnects=$(run_cmd "$LOG_FILE" timeout 5s journalctl -u sshd --since "1 hour ago" 2>/dev/null | grep -Ei "Connection closed|Disconnecting" | wc -l | tr -d ' \n\t\r' || echo 0)
    else
        disconnects=$(grep -Ei "Connection closed|Disconnecting" /var/log/auth.log 2>/dev/null | grep "$(date '+%b %e')" | wc -l | tr -d ' \n\t\r' || echo 0)
    fi

    if ! [[ "$disconnects" =~ ^[0-9]+$ ]]; then
        disconnects=0
    fi
    log "→ 最近1小时 SSH 断开次数: $disconnects" "$LOG_FILE"

    # 断开次数过多则警告
    if [ "$disconnects" -ge 10 ]; then
        send_alert "频繁 SSH 断开" "检测到过去1小时内 $disconnects 次 SSH 断开。请检查不稳定性或 fail2ban 误封。" "WARN" "monitor_ssh_stability ($LOG_FILE)"
    fi

    ## [2] 当前登录会话数
    local active_sessions=0
    active_sessions=$(who 2>/dev/null | wc -l | tr -d ' \n\t\r' || echo 0)
    if ! [[ "$active_sessions" =~ ^[0-9]+$ ]]; then
        active_sessions=0
    fi
    
    log "→ 当前活动 SSH 会话数: $active_sessions" "$LOG_FILE"

    if [ "$active_sessions" -gt 50 ]; then
        send_alert "活动会话过多" "当前有 $active_sessions 个活动用户会话。可能存在滥用或拒绝服务攻击。" "WARN" "monitor_ssh_stability ($LOG_FILE)"
    fi

    ## [3] CLOSE_WAIT 会话数（可能的套接字泄漏）
    local close_wait_count=0
    close_wait_count=$(run_cmd "$LOG_FILE" timeout 5s ss -tan 2>/dev/null | grep CLOSE-WAIT | wc -l | tr -d ' \n\t\r' || echo 0)
    
    if ! [[ "$close_wait_count" =~ ^[0-9]+$ ]]; then
        close_wait_count=0
    fi
    log "→ 当前 CLOSE_WAIT 套接字数: $close_wait_count" "$LOG_FILE"

    if [ "$close_wait_count" -gt 100 ]; then
        send_alert "过多 CLOSE_WAIT" "检测到 $close_wait_count 个 CLOSE_WAIT 套接字。可能存在套接字泄漏或会话卡死。" "WARN" "monitor_ssh_stability ($LOG_FILE)"
    fi

    ## [4] SSH 配置稳定性检查
    local ClientAliveInterval=0
    local ClientAliveCountMax=3
    local ssh_config="/etc/ssh/sshd_config"
    
    if [ -f "$ssh_config" ]; then
        ClientAliveInterval=$(grep -E "^[[:space:]]*ClientAliveInterval" "$ssh_config" 2>/dev/null | awk '{print $2}' || echo "0")
        ClientAliveCountMax=$(grep -E "^[[:space:]]*ClientAliveCountMax" "$ssh_config" 2>/dev/null | awk '{print $2}' || echo "3")
    elif [ -d "/etc/ssh/sshd_config.d" ]; then
        for conf_file in /etc/ssh/sshd_config.d/*.conf; do
            if [ -f "$conf_file" ]; then
                if grep -q "ClientAliveInterval" "$conf_file"; then
                    ClientAliveInterval=$(grep -E "^[[:space:]]*ClientAliveInterval" "$conf_file" | awk '{print $2}')
                fi
                if grep -q "ClientAliveCountMax" "$conf_file"; then
                    ClientAliveCountMax=$(grep -E "^[[:space:]]*ClientAliveCountMax" "$conf_file" | awk '{print $2}')
                fi
            fi
        done
    fi
    
    log "→ SSH 保活配置: ClientAliveInterval=$ClientAliveInterval, ClientAliveCountMax=$ClientAliveCountMax" "$LOG_FILE"
    
    if [ "$ClientAliveInterval" = "0" ] || [ "$ClientAliveInterval" -gt 60 ]; then
        send_alert "SSH 配置问题" "SSH ClientAliveInterval 为 $ClientAliveInterval。建议设置为30（以便及早检测无效会话）。" "WARN" "monitor_ssh_stability ($LOG_FILE)"
    fi
}

# SSH 安全监控（关注登录失败、封禁 IP、暴力破解攻击等）
monitor_ssh_security() {
    local LOG_FILE="$LOG_BASE/ssh_security_$(date +%F).log"
    log "====== SSH 安全监控 ======" "$LOG_FILE"

    ## [1] SSH 登录失败尝试检测（日志文件分析）
    local failed_logins=0
    failed_logins=$(run_cmd "$LOG_FILE" grep -i "Failed password" /var/log/auth.log 2>/dev/null | wc -l | tr -d ' \n\t\r' || echo 0)
    [[ "$failed_logins" =~ ^[0-9]+$ ]] || failed_logins=0
    
    log "→ SSH 登录失败总次数: $failed_logins" "$LOG_FILE"
    
    # 最近失败次数（如果有 journalctl，时间过滤更准确）
    local recent_failures=0
    if command -v journalctl &>/dev/null; then
        recent_failures=$(run_cmd "$LOG_FILE" timeout 5s journalctl -u sshd --since "3 hour ago" 2>/dev/null | grep -c "Failed password" || echo 0)
        [[ "$recent_failures" =~ ^[0-9]+$ ]] || recent_failures=0
        log "→ 最近3小时 SSH 登录失败次数: $recent_failures" "$LOG_FILE"
    fi
    
    # 生成告警（优先使用最近失败次数，否则用总次数）
    local threshold_count=${recent_failures:-$failed_logins}
    local threshold=20
    
    # 判断是否超过阈值
    if [[ "$threshold_count" =~ ^[0-9]+$ ]] && [ "$threshold_count" -ge "$threshold" ]; then
        # 攻击者 IP 统计（只取前5个）
        local attacking_ips
        attacking_ips=$(run_cmd "$LOG_FILE" grep "Failed password" /var/log/auth.log 2>/dev/null | awk '{print $11}' | sort | uniq -c | sort -nr | head -5 || echo "无法提取 IP 信息。")
        send_alert "SSH 暴力破解尝试" \
            "检测到 $threshold_count 次 SSH 登录失败尝试。\n攻击者 IP Top5:\n$attacking_ips" \
            "WARN" "monitor_ssh_security ($LOG_FILE)"
    fi

    ## [2] fail2ban 状态检测（若已安装）
    if command -v fail2ban-client &> /dev/null; then
        log "--- Fail2Ban 状态 ---" "$LOG_FILE"
        
        # 检查 fail2ban 服务状态
        if ! systemctl is-active --quiet fail2ban; then
            send_alert "Fail2Ban 未运行" "fail2ban 服务未启动。" "WARN" "monitor_ssh_security ($LOG_FILE)"
            log "→ fail2ban 服务未运行" "$LOG_FILE"
            return
        fi
        
        # 检查 sshd jail 状态
        local status_output
        status_output=$(run_cmd "$LOG_FILE" timeout 5s fail2ban-client status sshd 2>&1 || echo "获取 fail2ban 状态失败")
        echo "$status_output" >> "$LOG_FILE"
        
        # 提取被封禁 IP
        local banned_ips
        banned_ips=$(echo "$status_output" | grep 'Banned IP list:' | cut -d: -f2- | tr -s ' ' | sed 's/^ //' || echo "")
        
        if [ -n "$banned_ips" ]; then
            local banned_count=$(echo "$banned_ips" | wc -w || echo 0)
            log "→ 当前封禁 IP 数: $banned_count" "$LOG_FILE"
            
            # 保存 IP 列表并检测新增 IP
            local banned_ips_file="/tmp/fail2ban_current_ips.txt"
            local banned_ips_old_file="/tmp/fail2ban_prev_ips.txt"
            
            echo "$banned_ips" | tr ' ' '\n' | sort > "$banned_ips_file" || true
            
            local new_ips=""
            if [ -f "$banned_ips_old_file" ]; then
                new_ips=$(comm -23 <(sort "$banned_ips_file") <(sort "$banned_ips_old_file") || echo "$banned_ips")
            else
                new_ips="$banned_ips"
            fi
            
            cp "$banned_ips_file" "$banned_ips_old_file" || true
            
            # 若有新封禁 IP，发送告警（排除空白）
            if [ -n "$(echo "$new_ips" | tr -d '[:space:]')" ]; then
                local timestamp=$(date '+%F %T')
                echo "[$timestamp] 封禁 IP: $banned_ips" >> "$LOG_BASE/fail2ban_ip_history.log" || true
                # 发送到 Slack 前写入调试日志
                echo "新增封禁 IP (用于 Slack): $new_ips" >> "$LOG_FILE"
                
                send_alert "Fail2Ban 新封禁 IP" "新增封禁 IP:\n$new_ips" "WARN" "monitor_ssh_security ($LOG_FILE)"
            else
                log "→ 未检测到新增封禁 IP。" "$LOG_FILE"
            fi
        fi  
        # 分析重复封禁 IP（存在 fail2ban_ip_history.log 时）
        if [ -f "$LOG_BASE/fail2ban_ip_history.log" ]; then
            log "--- 重复封禁者分析 ---" "$LOG_FILE"
            run_cmd "$LOG_FILE" tail -n 1000 "$LOG_BASE/fail2ban_ip_history.log" | \
                grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort | uniq -c | sort -nr | head -5 > /tmp/fail2ban_stats.txt || true

            cat /tmp/fail2ban_stats.txt >> "$LOG_FILE" || true

            while read -r count ip; do
                if [[ "$count" =~ ^[0-9]+$ ]] && [ "$count" -ge 5 ]; then
                    send_alert "重复 Fail2Ban 封禁者" \
                        "IP $ip 最近被封禁 $count 次。\n建议在防火墙层面永久封禁。" \
                        "WARN" "monitor_ssh_security ($LOG_FILE)"
                fi
            done < /tmp/fail2ban_stats.txt 2>/dev/null || true
        fi

    else
        log "→ 未安装 fail2ban" "$LOG_FILE"
        send_alert "Fail2Ban 缺失" "未安装 fail2ban。建议为服务器安全安装。" "WARN" "monitor_ssh_security ($LOG_FILE)"
    fi
}


# SSH 连接优化及自动管理函数
optimize_sshd_config() {
    local LOG_FILE="$LOG_BASE/ssh_optimize_config_$(date +%F).log"
    log "====== SSH 连接优化及自动管理 ======" "$LOG_FILE"
    local ssh_config="/etc/ssh/sshd_config"
    local need_reload=false

    declare -A CONFIGS=(
        [ClientAliveInterval]=30
        [ClientAliveCountMax]=3
        [TCPKeepAlive]=yes
        [MaxStartups]='20:50:100'
        [LoginGraceTime]=30
    )

    for param in "${!CONFIGS[@]}"; do
        local val="${CONFIGS[$param]}"
        local cur_val=$(grep -E "^[[:space:]]*$param" "$ssh_config" | awk '{print $2}' || echo "")

        if [ "$cur_val" != "$val" ]; then
            if grep -q "^[[:space:]]*$param" "$ssh_config"; then
                sed -i "s/^[[:space:]]*$param.*/$param $val/" "$ssh_config"
            else
                echo "$param $val" >> "$ssh_config"
            fi
            need_reload=true
            log "→ $param 已更新: $cur_val → $val" "$LOG_FILE"
        fi
    done

    if [ "$need_reload" = true ]; then
        systemctl reload sshd
        send_alert "SSH 配置优化" "sshd_config 优化配置已应用。" "INFO" "optimize_sshd_config"
    fi
}

# SSH 服务优先级调整 
prioritize_sshd_service() {
    local LOG_FILE="$LOG_BASE/ssh_priority_$(date +%F).log"
    log "====== SSH 服务优先级调整 ======" "$LOG_FILE"

    local pid=$(pgrep -f '^/usr/sbin/sshd' | head -1 || echo "")
    if [ -n "$pid" ]; then
        renice -10 "$pid" 2>/dev/null || true
        log "→ sshd PID $pid 优先级设为 -10" "$LOG_FILE"
    fi

    mkdir -p /etc/systemd/system/ssh.service.d || true
    cat << EOF > /etc/systemd/system/ssh.service.d/priority.conf || true
[Service]
CPUSchedulingPolicy=rr
CPUSchedulingPriority=99
IOSchedulingClass=realtime
IOSchedulingPriority=0
EOF
    systemctl daemon-reexec || true
    systemctl restart ssh || true
    send_alert "sshd 优先级应用" "sshd systemd 优先级已提升。" "INFO" "prioritize_sshd_service"
}

# 系统资源自动管理函数
manage_system_resources() {
    local LOG_FILE="$LOG_BASE/resource_manage_$(date +%F).log"
    log "====== 系统资源管理 ======" "$LOG_FILE"
    
    # [1] 系统负载检查
    local load_avg cpu_count load_threshold
    load_avg=$(awk '{print $1}' /proc/loadavg)
    cpu_count=$(nproc)
    load_threshold=$(echo "$cpu_count * 1.5" | bc)
    
    log "→ 系统负载: $load_avg (CPU 核数: $cpu_count, 阈值: $load_threshold)" "$LOG_FILE"
    
    # [2] 负载高时自动处理
    if (( $(echo "$load_avg > $load_threshold" | bc -l) )); then
        log "→ 系统负载过高 ($load_avg > $load_threshold)" "$LOG_FILE"
        send_alert "高系统负载" "系统负载 ($load_avg) 超过阈值 ($load_threshold)。" "WARN" "manage_system_resources ($LOG_FILE)"
        
        # 记录负载最高的进程
        log "--- CPU 使用最高进程 ---" "$LOG_FILE"
        ps -eo pid,ppid,user,pcpu,pmem,cmd --sort=-%cpu | head -10 >> "$LOG_FILE"
        
        # 自动资源管理（ENABLE_SELF_HEALING 为 true 时）
        if [ "$ENABLE_SELF_HEALING" = true ]; then
            # 调整优先级的进程（排除白名单）
            for pid in $(ps -eo pid,pcpu --sort=-%cpu | awk 'NR>1 && $2>30 {print $1}' | head -5); do
                # 排除重要进程（systemd, sshd, init 等）
                if ! ps -p "$pid" -o cmd= | grep -qE "(systemd|sshd|init|kernel|bash)"; then
                    local current_nice
                    current_nice=$(ps -o nice= -p "$pid")
                    
                    if [ "$current_nice" -lt 10 ]; then
                        log "→ 降低 PID $pid 优先级 (当前 nice: $current_nice)" "$LOG_FILE"
                        renice +15 "$pid" >> "$LOG_FILE" 2>&1 || true
                        
                        # 同时调整 I/O 优先级
                        if command -v ionice &> /dev/null; then
                            ionice -c 3 -p "$pid" >> "$LOG_FILE" 2>&1 || true
                            log "→ 将 PID $pid 的 I/O 类别设为空闲" "$LOG_FILE"
                        fi
                    fi
                fi
            done
            
            # 内核参数优化
            if ! grep -q "vm.swappiness" /etc/sysctl.conf; then
                echo "vm.swappiness=10" >> /etc/sysctl.conf
                sysctl -w vm.swappiness=10 >> "$LOG_FILE" 2>&1 || true
                log "→ 设置 vm.swappiness=10 减少交换空间使用" "$LOG_FILE"
            fi
            
            # 调整 OOM 分数（非重要进程）
            for pid in $(ps -eo pid,pmem --sort=-%mem | awk 'NR>1 && $2>5 {print $1}' | head -5); do
                if ! ps -p "$pid" -o cmd= | grep -qE "(systemd|sshd|init|kernel|bash)"; then
                    echo 500 > /proc/$pid/oom_score_adj 2>> "$LOG_FILE" || true
                    log "→ 增加 PID $pid 的 OOM 杀死优先级" "$LOG_FILE"
                fi
            done
        fi
    fi
    
    # [3] 内存使用检查与管理
    local mem_total mem_avail mem_percentage
    mem_total=$(free -m | awk '/^Mem:/ {print $2}')
    mem_avail=$(free -m | awk '/^Mem:/ {print $7}')
    mem_percentage=$(echo "scale=2; ($mem_total - $mem_avail) * 100 / $mem_total" | bc)
    
    log "→ 内存使用率: ${mem_percentage}% (可用: ${mem_avail}MB / 总计: ${mem_total}MB)" "$LOG_FILE"
    
    # 内存紧张时处理
    if (( $(echo "$mem_percentage > 90" | bc -l) )); then
        send_alert "内存不足警告" "系统内存使用率非常高 (${mem_percentage}%)。" "WARN" "manage_system_resources ($LOG_FILE)"
        
        if [ "$ENABLE_SELF_HEALING" = true ]; then
            # 释放缓存
            sync
            if [ -w "/proc/sys/vm/drop_caches" ]; then
                echo 3 > /proc/sys/vm/drop_caches 2>/dev/null || log "释放缓存失败" "$LOG_FILE"
            else
                log "无权限释放缓存" "$LOG_FILE"
            fi
            log "→ 释放文件系统缓存以释放内存" "$LOG_FILE"
            
            # 重新挂载交换分区
            run_cmd "$LOG_FILE" swapoff -a && run_cmd "$LOG_FILE" swapon -a || true
            log "→ 重新挂载交换分区以减少碎片" "$LOG_FILE"
        fi
    fi
    
    # [4] 磁盘 I/O 状态检查
    if command -v iostat &> /dev/null; then
        log "--- 磁盘 I/O 统计 ---" "$LOG_FILE"
        iostat -x 1 2 | grep -v "loop\|ram" >> "$LOG_FILE" 2>&1 || true
        
        # 检测高 I/O 等待
        local io_wait
        io_wait=$(vmstat 1 2 | tail -1 | awk '{print $16}')
        
        if [ "$io_wait" -gt 30 ]; then
            send_alert "高 I/O 等待" "系统 I/O 等待时间高 (${io_wait}%)。" "WARN" "manage_system_resources ($LOG_FILE)"
            
            if [ "$ENABLE_SELF_HEALING" = true ] && command -v ionice &> /dev/null; then
                # 查找高 I/O 使用进程
                for pid in $(iotop -b -n 1 -o | head -n 10 | awk '{print $1}' | grep -E '[0-9]+'); do
                    if [ "$pid" -gt 1 ] && ! ps -p "$pid" -o cmd= | grep -qE "(systemd|sshd|init)"; then
                        ionice -c 3 -p "$pid" >> "$LOG_FILE" 2>&1 || true
                        log "→ 将高 I/O 进程 PID $pid 的 I/O 类别设为空闲" "$LOG_FILE"
                    fi
                done
            fi
        fi
    else
        send_alert "缺少 iostat" "未检测到 iostat 命令，无法监控 I/O 等待。" "WARN" "manage_system_resources ($LOG_FILE)"
    fi
}

# === 新增: 资源管理重构 ===
manage_high_load() {
    local LOG_FILE="$LOG_BASE/high_load_$(date +%F).log"
    log "====== 高系统负载管理 ======" "$LOG_FILE"

    local load_avg=0 cpu_count=1 load_threshold=0
    
    load_avg=$(awk '{print $1}' /proc/loadavg 2>/dev/null || echo "0")
    cpu_count=$(nproc 2>/dev/null || echo "1")
    
    if command -v bc &>/dev/null; then
        load_threshold=$(echo "$cpu_count * 1.5" | bc -l 2>/dev/null || echo "$cpu_count")
    else
        load_threshold=$((cpu_count * 3 / 2))
    fi

    log "系统负载: $load_avg (CPU 核数: $cpu_count, 阈值: $load_threshold)" "$LOG_FILE"

    local is_overloaded=0
    if command -v bc &>/dev/null; then
        is_overloaded=$(echo "$load_avg > $load_threshold" | bc -l 2>/dev/null || echo "0")
    else
        local load_int=${load_avg%.*}
        [ "$load_int" -gt "$load_threshold" ] && is_overloaded=1 || is_overloaded=0
    fi

    if [ "$is_overloaded" -eq 1 ]; then
        send_alert "高系统负载" "系统负载 ($load_avg) 超过阈值 ($load_threshold)。" "WARN" "manage_high_load ($LOG_FILE)"

        log "--- CPU 使用最高进程 ---" "$LOG_FILE"
        ps -eo pid,ppid,user,pcpu,pmem,cmd --sort=-%cpu 2>/dev/null | head -10 >> "$LOG_FILE" || true
    fi
}

manage_memory_pressure() {
    local LOG_FILE="$LOG_BASE/mem_pressure_$(date +%F).log"
    log "====== 内存使用管理 ======" "$LOG_FILE"

    local mem_total mem_avail mem_percentage
    mem_total=$(free -m | awk '/^Mem:/ {print $2}')
    mem_avail=$(free -m | awk '/^Mem:/ {print $7}')
    mem_percentage=$(echo "scale=2; ($mem_total - $mem_avail) * 100 / $mem_total" | bc)

    log "内存使用率: ${mem_percentage}% (可用: ${mem_avail}MB / 总计: ${mem_total}MB)" "$LOG_FILE"

    if (( $(echo "$mem_percentage > 90" | bc -l) )); then
        send_alert "内存不足警告" "系统内存使用率非常高 (${mem_percentage}%)。" "WARN" "manage_memory_pressure ($LOG_FILE)"

        sync && echo 3 > /proc/sys/vm/drop_caches 2>> "$LOG_FILE" || true
        log "→ 释放文件系统缓存以释放内存" "$LOG_FILE"

        # swapoff -a && swapon -a >> "$LOG_FILE" 2>&1 || true
        run_cmd "$LOG_FILE" swapoff -a && run_cmd "$LOG_FILE" swapon -a || true
        log "→ 重新挂载交换分区以减少碎片" "$LOG_FILE"
    fi
}

manage_io_bottleneck() {
    local LOG_FILE="$LOG_BASE/io_bottleneck_$(date +%F).log"
    log "====== I/O管理 ======" "$LOG_FILE"

    if command -v iostat &> /dev/null; then
        iostat -x 1 2 | grep -v "loop\|ram" >> "$LOG_FILE" 2>&1 || true
        local io_wait
        io_wait=$(vmstat 1 2 | tail -1 | awk '{print $16}')

        if [ "$io_wait" -gt 30 ]; then
            send_alert "高 I/O 等待" "系统存在高 I/O 等待时间 (${io_wait}%)。" "WARN" "manage_io_bottleneck ($LOG_FILE)"
        fi
    else
        send_alert "缺少 iostat" "未检测到 iostat 命令，无法监控 I/O 等待。" "WARN" "manage_io_bottleneck ($LOG_FILE)"
    fi
}

# 兼容性包装函数
monitor_system_resources() {
    local LOG_FILE="$LOG_BASE/resource_monitor_$(date +%F).log"
    log "====== 资源监控 ======" "$LOG_FILE"
    log "→ 使用重构后的资源监控函数" "$LOG_FILE"
    
    manage_high_load
    manage_memory_pressure
    manage_io_bottleneck
}

# 清理文件函数
clean_files() {
    local dir="$1"
    local log_file="$2"

    # 获取文件夹总大小（单位 GB）
    local dir_size
    dir_size=$(du -sBG "$dir" | awk '{print $1}' | sed 's/[^0-9]*//g')  # 获取文件夹大小，单位为GB

    # 获取目标保留的空间（目标总容量 - 预留空间）
    local target_size
    target_size=$(($dir_size - $TARGET_FREE_GB))  # 需要清理的目标大小

    # 如果文件夹大小小于阈值或目标空间，直接返回
    if [ "$dir_size" -le "$SIZE_THRESHOLD_GB" ]; then
        log "→ 文件夹 $dir 的总大小 ($dir_size GB) 未超过阈值 ($SIZE_THRESHOLD_GB GB)，无需清理。" "$log_file"
        return
    fi

    log "→ 文件夹 $dir 的总大小 ($dir_size GB) 超过了阈值 ($SIZE_THRESHOLD_GB GB)，需要清理文件以释放空间。" "$log_file"
    
    # 查找并按日期排序，删除最早的文件，直到满足目标空间需求
    local files_to_delete
    files_to_delete=$(find "$dir" -type f -mtime +$DELETE_OLDER_THAN_DAYS -printf "%T@ %p\n" | sort -n)

    # 计算需要删除的空间
    local total_deleted_space=0
    local deleted_files=""
    
    # 按文件创建日期排序并逐步删除，直到释放足够空间
    while IFS= read -r line; do
        local file_size
        local file_path
        file_size=$(stat --format="%s" "$(echo $line | awk '{print $2}')")  # 获取文件大小
        file_path=$(echo $line | awk '{print $2}')

        # 累加已删除的空间
        total_deleted_space=$((total_deleted_space + file_size))

        # 记录删除的文件
        deleted_files="$deleted_files$file_path\n"

        # 删除文件
        rm -f "$file_path"
        log "→ 删除文件: $file_path" "$log_file"

        # 如果已释放足够空间，停止删除
        if [ "$total_deleted_space" -ge "$target_size" ]; then
            break
        fi
    done <<< "$files_to_delete"

    # 如果有文件被删除，发送告警
    if [ -n "$deleted_files" ]; then
        send_alert "文件清理" "清理了以下文件以释放空间:\n$deleted_files" "INFO" "monitor_and_clean_files ($log_file)"
    else
        log "→ 没有足够旧的文件可清理。" "$log_file"
    fi
}

# [监控和清理文件功能]
monitor_and_clean_files() {
    local LOG_FILE="$LOG_BASE/file_cleanup_$(date +%F).log"
    log "====== 文件清理监控 ======" "$LOG_FILE"

    # 遍历配置的文件路径，监控并清理超出阈值的文件
    for dir in "${FILE_PATHS[@]}"; do
        # 检查文件夹是否存在
        if [ ! -d "$dir" ]; then
            log "⚠️ 文件路径 $dir 不存在" "$LOG_FILE"
            continue
        fi

        clean_files "$dir" "$LOG_FILE"
    done
}

######################## 日志清理与汇总 ##############################
# 清理（删除或压缩）旧日志文件，
# 并生成每日摘要报告以通过邮件发送。
# 参考：解压缩：tar -zxvf logs_2025-08-12.tar.gz --strip-components=5
clean_old_logs() {
    local LOG_FILE="$LOG_BASE/log_cleanup_$(date +%F).log"
    log "====== 旧日志清理 ======" "$LOG_FILE"
    # 检查并创建必要目录
    mkdir -p "$LOG_BASE" "$LOG_ARCHIVE_DIR" "$LOG_ALERTS_DIR" 2>/dev/null || true

    # [1] 日志文件压缩处理：除当天日志外，压缩文件名符合 *_YYYY-MM-DD.log 格式的日志文件
    local today=$(date +%F)
    local files_to_compress=()
    
    # 查找非当天日志文件
    mapfile -t found_logs < <(find "$LOG_BASE" -maxdepth 1 -type f -name "*_*.log" ! -name "*.tar.gz" 2>/dev/null || true)
    
    for file in "${found_logs[@]}"; do
        # 确认文件存在
        [ -f "$file" ] || continue
        
        log_date=$(basename "$file" | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2}' || echo "")
        [[ "$log_date" == "$today" || -z "$log_date" ]] && continue
        files_to_compress+=("$file")
    done
    
    if [ ${#files_to_compress[@]} -eq 0 ]; then
        log "→ 无历史日志需要压缩。" "$LOG_FILE"
    else
        # 按日期分组并压缩
        local unique_dates
        unique_dates=$(printf '%s\n' "${files_to_compress[@]}" | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2}' | sort -u)
        
        for date in $unique_dates; do
            log "--- 正在压缩 $date 的日志 ---" "$LOG_FILE"
            local matched_files=()
            
            for f in "${files_to_compress[@]}"; do
                [[ "$f" =~ $date ]] && matched_files+=("$(basename "$f")")
            done
            
            if [ ${#matched_files[@]} -gt 0 ]; then
                pushd "$LOG_BASE" >/dev/null 2>&1 || continue
                
                # 进行压缩
                if tar -czf "$LOG_ARCHIVE_DIR/${date}_logs.tar.gz" "${matched_files[@]}" 2>/dev/null; then
                    # 删除原始文件
                    for file in "${matched_files[@]}"; do
                        rm -f "$file" 2>/dev/null || true
                    done
                    log "→ 成功压缩 $date 的 ${#matched_files[@]} 个日志" "$LOG_FILE"
                else
                    log "❌ 压缩 $date 日志失败" "$LOG_FILE"
                fi
                
                popd >/dev/null 2>&1 || true
            fi
        done
    fi
    
    # [2] 删除过期文件
    find "$LOG_ARCHIVE_DIR" -type f -name "*.tar.gz" -mtime +$RETENTION_DAYS -delete 2>/dev/null || true
    find "$LOG_BASE" -type f -name "*.log" -mtime +$RETENTION_DAYS -delete 2>/dev/null || true
    find "$LOG_ALERTS_DIR" -type f -name "run_alerts_*.log" -mtime +$RETENTION_DAYS -delete 2>/dev/null || true
    find "$LOG_BASE" -type f -name "alert_history.log" -mtime +90 -exec truncate -s 0 {} \;


    # [3] 检查日志目录容量
    if [ -d "$LOG_BASE" ]; then
        local total_size_kb
        total_size_kb=$(du -sk "$LOG_BASE" 2>/dev/null | awk '{print $1}' || echo 0)
        
        if [[ "$total_size_kb" =~ ^[0-9]+$ ]] && [ "$total_size_kb" -gt "$SIZE_THRESHOLD_KB" ]; then
            send_alert "日志目录大小" "日志目录超过 ${SIZE_THRESHOLD_KB} KB (当前大小: ${total_size_kb} KB)" "WARN" "clean_old_logs ($LOG_FILE)"
        fi
    fi
    
    # [4] 清理缓存
    rm -f "$LOG_BASE/.alert_sent_cache" 2>/dev/null || true
    
    log "→ clean_old_logs 执行完毕" "$LOG_FILE"
    return 0
}


# generate_summary(): 生成服务器状态摘要报告，若存在CRIT/WARN警告则发送完整邮件
# - 每次执行时保存为 'summary_current_<date>.log'，上一次摘要备份为 'summary_prev_<date>.log'。
# - 完整内容不记录到GLOBAL_LOG，仅记录完成消息。
generate_summary() {
    local SUMMARY_FILE="$LOG_BASE/summary_current_$(date +%F).log"
    local PREV_SUMMARY_FILE="$LOG_BASE/summary_prev_$(date +%F).log"

    # 备份已有摘要日志
    if [ -f "$SUMMARY_FILE" ]; then
        mv "$SUMMARY_FILE" "$PREV_SUMMARY_FILE"
    fi

    log "====== 摘要报告 ======" "$SUMMARY_FILE"


    log "--- 磁盘使用摘要 ---" "$SUMMARY_FILE"
    local disk_summary
    disk_summary=$(df -h | grep -vE "tmpfs|udev|loop")
    echo "$disk_summary" >> "$SUMMARY_FILE"

    local high_disks=$(echo "$disk_summary" | awk '$5+0 > 80 {print $0}')

    
    log "--- 磁盘使用变化 ---" "$SUMMARY_FILE"
    if [ -f "$LOG_BASE/.prev_disk_usage" ]; then
        local prev_disk_usage=$(cat "$LOG_BASE/.prev_disk_usage")
        echo "$prev_disk_usage" >> "$SUMMARY_FILE"
    else
        echo "(无先前使用数据)" >> "$SUMMARY_FILE"
    fi

    log "--- LVM/Overlay/tmpfs 文件系统 ---" "$SUMMARY_FILE"
    local lvm_info=$(df -hT | grep -E "lvm2|overlay|tmpfs")
    echo "$lvm_info" >> "$SUMMARY_FILE"


    log "--- 内存使用摘要 ---" "$SUMMARY_FILE"
    local mem_usage=$(free -h)
    echo "$mem_usage" >> "$SUMMARY_FILE"

    local mem_line=$(echo "$mem_usage" | grep -i "^Mem:")



    log "--- CPU 使用摘要 ---" "$SUMMARY_FILE"
    local cpu_info=$(top -b -n 1 | head -15)
    echo "$cpu_info" >> "$SUMMARY_FILE"

    log "--- 负载平均 ---" "$SUMMARY_FILE"
    local uptime_info=$(uptime)
    echo "$uptime_info" >> "$SUMMARY_FILE"

    local load_avg=$(echo "$uptime_info" | sed 's/.*load average: //')



    log "--- 重启历史 ---" "$SUMMARY_FILE"
    local reboot_info
    reboot_info=$(uptime -s && last reboot | head -5)
    echo "$reboot_info" >> "$SUMMARY_FILE"

    log "--- 内核日志 (dmesg尾部) ---" "$SUMMARY_FILE"
    local dmesg_tail=$(dmesg -T | tail -10)
    echo "$dmesg_tail" >> "$SUMMARY_FILE"

    log "--- 服务状态摘要 ---" "$SUMMARY_FILE"
    for svc in "${SERVICES[@]}"; do
        local svc_status=$(systemctl is-active "$svc" 2>/dev/null || echo "unknown")
        echo "$svc: $svc_status" >> "$SUMMARY_FILE"
    done

    log "--- 最近警告摘要 ---" "$SUMMARY_FILE"
    if [ -f "$RUN_ALERTS_FILE" ]; then
        local alerts=$(tail -n 20 "$RUN_ALERTS_FILE")
        echo "$alerts" >> "$SUMMARY_FILE"

        local alerts_summary=$(echo "$alerts" | grep -E "\[CRIT\]|\[WARN\]" | tail -5)
    fi

    # 发送条件：最近有CRIT或WARN
    if grep -q "\[CRIT\]\|\[WARN\]" "$RUN_ALERTS_FILE"; then
        # 发送完整邮件
        mail -s "[$HOST_ID] 服务器监控摘要 - $(hostname) - $(date +%F)" "$ALERT_EMAIL" < "$SUMMARY_FILE"
    fi
}


################## 日志清理与汇总 #########################################
run_monitoring() {
    local MONITOR_LOG="$LOG_BASE/monitor_$(date +%F).log"
    log "=======================================================================" "$MONITOR_LOG"
    log "=== 服务器监控启动 ($(date)) ===" "$MONITOR_LOG"

    ### 备份开始前备份 bash_history
    safe_run backup_bash_history
    ### [系统及资源摘要]
    safe_run collect_system_summary
    safe_run check_disk_usage
    safe_run check_io_heavy_processes
    safe_run check_network_status
    safe_run check_docker_volume_usage
    safe_run check_process_usage

    ### [服务状态及安全监控]
    safe_run check_services
    safe_run check_system_temperature
    safe_run analyze_system_logs
    safe_run manage_zombie_processes
    safe_run analyze_container_logs
    
    ### [SSH及安全设置检查]
    safe_run monitor_ssh_stability    # SSH连接稳定性监控
    safe_run monitor_ssh_security     # SSH安全监控（整合了check_fail2ban_status及登录失败分析）
    # SSH自动恢复功能仅当ENABLE_SELF_HEALING为true时执行
    if [ "$ENABLE_SELF_HEALING" = true ]; then
        safe_run optimize_sshd_config     # SSH配置优化
        safe_run prioritize_sshd_service  # SSH服务优先级调整
    fi

    
    ### [资源使用自动管理与清理]
    safe_run monitor_system_resources   
    # 条件执行（资源自动优化风险较大）
    if [ "$ENABLE_SELF_HEALING" = true ]; then
        safe_run server_self_healing 
    fi
  
    safe_run clean_old_logs
    safe_run monitor_and_clean_files   # 文件清理监控
    ### [结果摘要及通知发送]
    safe_run generate_summary

    log "=== 服务器监控完成 ($(date)) ===" "$MONITOR_LOG"
    log "=======================================================================" "$MONITOR_LOG"
}

###################################

# 确认脚本以root权限执行
if [ "$EUID" -ne 0 ]; then
    echo "本脚本必须以root权限运行"
    exit 1
fi

# 如果为summary_only模式
if [ "${1:-}" = "summary_only" ]; then
    safe_run generate_summary
    exit 0
fi

# 执行完整监控流程
run_monitoring

exit 0

# 手动执行 :   $ sudo bash ./server_monitoring.sh 
#              $ sudo bash ./server_monitoring.sh summary_only
# 进程确认 : $ ps aux | grep server_monitoring.sh




