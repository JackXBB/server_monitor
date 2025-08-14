server_monitoring.sh  
服务器监控自动化脚本（2025.08）

📌 脚本简介  
本脚本面向 Linux 服务器，周期性地检测各类资源状态与安全事件，并可自动修复、主动推送Email 告警、生成每日摘要报告。
目标：提升线上服务器的稳定性与安全性。

主要监控项  
• 系统资源：CPU、内存、磁盘、负载  
• 进程/服务状态监控与自动恢复  
• Docker 容器状态及日志  
• 网络 / SSH 稳定性与安全  
• 僵尸进程 / 日志异常与实时告警  
• bash history 自动备份  
• 每日自动摘要报告生成与推送  

📂 目录结构  
├── server_monitoring.sh               # 主监控脚本  
├── install_server_monitoring.sh       # 自动化部署/卸载监控脚本  
├── monitor.conf                       # 可配置项
└── log/  
    ├── *.log                          # 各功能日志  
    ├── archive/                       # 旧日志压缩包  
    └── run_alerts_*.log               # 单次运行告警汇总  

🔧 核心功能速览  
类别            说明  
系统概览        uptime、CPU/内存/磁盘/网络、登录用户  
磁盘监控        容量阈值、inode、突增检测、无用文件提示  
Docker 卷监控   各卷使用率检查；未安装则告警  
网络监控        连接状态、带宽、ping 失败、DNS 解析错误  
进程监控        高负载进程自动结束或重启容器  
I/O 过载        iotop / pidstat / vmstat 排查瓶颈  
服务状态        nginx、sshd 等关键服务 & 容器状态  
系统温度        lm-sensors 检测，超温即告警  
日志分析        journalctl / auth.log 分析（SSH 失败等）  
僵尸进程        检测 + SIGCHLD 处理，必要时重启容器   
日志清理        旧日志压缩/删除，每日生成摘要
文件清理        按文件夹总容量来判断是否需要清理，按日期排序文件，逐步清理文件直到释放足够的空间
