# 规范: 通用守护进程服务定义 (`service.toml` v1)

- **归档内部位置**: `.METADATA/service.toml`
- **Schema 版本**: `1`
- **设计目标**: 纯粹跨 Init 系统的声明式服务规范，**完全解耦于底层 Init 实现**。由对应 Init 系统的 `rclass/init-<provider>.toml` 模板引擎在 Rebuild 时自动渲染。

---

## 1. 规范示例

```toml
schema_version = 1

[service]
name = "sshd"
description = "OpenSSH Server Daemon"
command = ["/usr/sbin/sshd", "-D"]
stop_command = []
reload_command = ["/usr/bin/kill", "-HUP", "$MAINPID"]
user = "root"
group = "root"
working_dir = "/"
pid_file = "/run/sshd.pid"
restart = "always"             # "always" | "on-failure" | "no"
type = "simple"                # "simple" | "forking" | "notify" | "oneshot"
after = ["net", "syslog"]
before = []
runtime = ""                   # 绑定运行时，例如 "runtime/java:openjdk-21"
```

一个文件可以使用单数 `[service]` 声明一个服务，也可以使用一个或多个
`[[services]]` 声明来自同一构建配方的多个服务。每个服务可以通过 `package`
字段归属到主包或某个子包；服务名称在同一个文件中必须唯一。两种声明形式
最终会被 Sage 合并为同一个服务集合。

`type` 支持 `simple`、`forking`、`notify` 和 `oneshot`。具体 init provider
可以通过其 `supported_types` 声明可渲染的子集。

---

## 2. 声明式 Init 渲染工作流 (Zero Hardcoded Init in Engine)

```text
/etc/sage/system.toml [providers.init = "<provider>"]
                   │
                   ▼ (加载对应 rclass)
         rclass/init-<provider>.toml
                   │
                   ├─► 读取各个包的 .METADATA/service.toml
                   ├─► 展开 template 模板字符串
                   └─► 写入目标文件 /etc/init.d/<name> (mode 0755)
```

1. **引擎完全通用**: `sage-sys` 内部不包含任何针对特定 Init（如 OpenRC、Systemd、Loom、Runit、s6）的硬编码分支。
2. **完全可扩展**: 增加对新 Init 系统的支持，仅需在包仓库中添加 `rclass/init-<name>.toml`，无需重新编译 `sage` 二进制。
