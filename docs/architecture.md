# 架构与安全边界

## 目标

系统监控一个明确的 `(ecosystem, package, version)` 集合。当某个精确版本首次从官方
registry 快照消失时，立即并发查询全部镜像并按原始字节捕获；连续缺失确认独立进行，
只决定该捕获是否晋级为最终归档，不阻塞利用镜像同步时间差的抢救动作。

版本仍在官方站时，扫描器只读取发布元数据并预先缓存摘要，不下载制品。下架后镜像
副本必须优先匹配这个历史官方摘要；这样镜像不能仅靠修改自己的 metadata 替换样本。

“下架”只是恶意软件的一个候选信号，也可能是作者主动撤回、法律原因或 registry
维护操作。因此内部状态叫 `suspected_takedown`，不能未经外部证据直接当作已确认恶意。

## 数据流

```text
人工/API/将来的发现器
        │ observe 精确版本
        ▼
   SQLite watchlist ──定时 scan──► 官方 RegistryHook
        ▲                              │
        │ available: 清零               ├─ unknown: 不改变计数
        │                              │
        ├──── 首次 not_found ─────────► 并发镜像 RegistryHook
        │                                      │
        │                                      ▼
        │                          captured_pending_confirmation
        │                                      │
        └────── 连续 N 次 not_found ───────────┘
                                               │
                                               ▼
                                      confirmed archive state
                       │ 原始 artifact URL + 预期哈希
                       ▼
            受限流式下载器 ──► SHA-256 CAS + SQLite 证据
                                      │ read-only
                                      ▼
                         断网限额 materializer ──► 静态源码视图
                                      │
                         OpenSSF OSV `MAL-*` ──► malware 标签
```

此外还有两条与 watchlist 隔离的补充通道：

- npm coverage：把一个保守的历史 sequence 窗口切成 10,000 条的 batch，从最新 batch
  向过去入队；worker 每轮只处理固定数量的包，并以完整 packument 中的版本发布时间过滤最近
  7×24 小时。实时 `_changes` 事件也会立刻重新入队，因此历史回填不会挡住新发布。
- OpenSSF backfill：每小时同步 npm、PyPI、RubyGems、crates.io、Go、Maven 与 NuGet 的 `modified_id.csv`，只保存 `MAL-*` 报告，再按
  `modified` 倒序读取单条 OSV JSON。明确列出的 exact versions 会立即标记并从官方源与镜像
  尝试保存原始制品；withdrawn/更新报告通过关系表重新计算标签。

## 模块

- `RegistryHook`：生态无关接口，定义坐标规范化、官方精确版本探测、镜像制品解析。
- `HookFactory`：通用注册点。七个 registry 生态使用完全相同的调度状态机。
- `Database`：watchlist、探测事件、归档清单和扫描租约。
- `Detector`：只负责编排，不理解 npm/PyPI 元数据格式。
- `ArchiveStore`：流式下载、大小上限、重定向后域名复检、摘要校验和原子落盘。
- `artifact_viewer`：独立断网容器；校验 CAS SHA-256 后限额展开普通文件，生成 manifest。
- `OpenSSFEnricher`：按精确版本查询 OSV，仅合并 `MAL-*` 恶意包记录。
- `NpmCoverageScanner`：管理七天历史 batch、newest-first 队列和 coverage 统计。
- `OpenSSFFeedImporter`：同步官方恶意报告索引、回填历史记录并触发精确制品恢复。

添加生态只需实现并注册：

```python
class MavenHook(RegistryHook):
    ecosystem = "maven"
    # normalize(), probe(), artifacts()

HookFactory.register("maven", MavenHook)
```

同一个 hook 类型既可连接官方站，也可连接任意镜像；差异只在配置中的 `base_url`、
`name` 与 `allowed_artifact_hosts`。镜像返回的制品 URL 不能绕过其独立白名单。

## 检测状态机

1. `watching`：官方精确版本存在，或尚未达到缺失阈值。
2. `captured_pending_confirmation`：首次缺失后已从镜像抢到原始制品，仍在等待确认。
3. `suspected_takedown`：至少 `absence_threshold` 次 `not_found`，每次间隔至少
   `min_absence_interval_seconds`。
4. `archived_verified`：确认下架，且镜像字节匹配此前从官方站缓存的 SHA-256/SHA-512。
5. `archived_unverified`：确认下架但缺少独立官方强哈希；必须以隔离、待复核状态展示。

超时、限流、5xx、非法 JSON 和其他网络异常全部归为 `unknown`，绝不能增加缺失计数。
再次观察到官方版本会清零计数。默认需要三次、间隔一小时，防止一次瞬态 404 形成最终结论；
第一次缺失仍会立刻触发镜像抢救。
没有历史官方强摘要的包仍可隔离保存，但只能进入 `archived_unverified`，不能作为已验证证据展示。

## 生态制品语义

- npm：读取包 metadata 的 `versions[exact_version]`，从镜像的 `dist.tarball` 获取
  原始 `.tgz`，校验 `integrity` 中的 SHA-256/SHA-512（如果存在）以及 `shasum`。
- PyPI 官方：读取 `/pypi/{name}/{version}/json`；PyPI 镜像读取 PEP 503 Simple Index。
  两者都只选择 sdist，优先保留
  registry 发布的原始 `.tar.gz`；若项目只发布 `.zip` sdist，也不转换或重新打包。
  wheel 默认不归档。

- RubyGems：官方版本 API 提供精确版本与 SHA-256，归档原始 `.gem`；镜像只提供制品时，
  必须依靠先前缓存的官方摘要完成强校验。源码查看器只在断网容器中受限展开内层 `data.tar.gz`。
- crates.io：官方与镜像均读取 Cargo sparse index 的逐版本记录，以 `cksum` 校验原始 `.crate`；
  `yanked=true` 视为需要立即抢救的不可解析版本，但仍不会执行 Cargo。
- Go：按照官方 GOPROXY 协议读取精确 `.info` 并保存 module `.zip`；不会调用 `go` 命令。
- Maven：按标准 repository layout 检查 POM、保存 JAR，并在存在时核对 SHA-1 sidecar。
- NuGet：通过 V3 flat container 枚举精确版本并保存原始 NUPKG；不会调用 `dotnet` 或 `nuget`。

TypeScript 没有独立 registry；JavaScript 与 TypeScript 包都归入 npm，避免同一制品产生两套坐标。

PyPI Simple 镜像通过配置中的 `metadata_format=pypi-simple` 启用，不在调度器里写站点特例。

## 永不安装/执行的约束

- 代码中没有 package-manager subprocess，也没有任何生态的 install 路径。
- 采集器不解压、不读取归档成员、不动态导入下载内容，也不执行生命周期脚本。
- 下载目标只能是配置白名单内的 HTTP(S) host；HTTPS registry 不允许降级到 HTTP。
- 拒绝带 URL 凭据的地址；关闭自动重定向，在发出每一跳请求前重新验证目标。
- 元数据和制品分别受大小上限限制；写临时文件时同步计算摘要。
- 预期大小、SHA-256、SHA-512 或 npm SHA-1 不匹配时删除临时文件并记录错误。
- 成功对象以 `0440` 权限放入 `objects/sha256/<prefix>/<digest>`，旁边只写 JSON 证据。

静态源码预览是单独的 materializer，不是分析执行环境。它运行在 `network_mode: none`、
无 Linux capabilities、只读根文件系统、非 root 用户、内存/进程/CPU 限额的容器中；原始
CAS 只读挂载。它不会使用 `extractall`，只流式写普通文件，拒绝绝对路径、`..`、链接、
设备/特殊文件、加密 ZIP 和异常压缩比，并限制成员数、单文件大小与总展开大小。Web 对输出
只有只读挂载，文件 API 还要求路径存在于 manifest 白名单。

## 发现与调度

“候选发现”与“下架确认”保持分离。npm 发现器消费 `_changes` 游标流，PyPI 发现器消费
官方 mirroring journal；两者都只为发生变化的包读取一次 metadata 并保存版本快照。
当新快照缺少旧版本时，才把该精确版本写入
watchlist，并立即触发并发镜像抢救，再由独立的连续缺失状态机确认。这避免每天对全部历史版本逐一请求。
实时删除检测首次启动仍从最新游标开始，避免把历史维护者撤包误判成刚发生的下架。与它分离的
coverage scanner 会用 3,000,000 个 sequence 的保守窗口逐批建立最近七天视图；sequence
本身不含时间戳，所以最终是否属于七天窗口只以官方 packument 的发布时间判断。OpenSSF
backfill 则独立覆盖官方已知恶意报告，不需要等包先被删除。

前端服务仅监听 `127.0.0.1:8787`，公网流量必须经过 Cloudflare Tunnel 和 Access。
浏览器可查看元数据、静态文本源码或触发强制附件下载。Web 服务自身没有归档解析器；下载响应固定为
`application/octet-stream`、`Content-Disposition: attachment` 和 `nosniff`。源码内容
通过 JSON 和 DOM `textContent` 显示，不会以内联 HTML 或脚本执行。

每五分钟运行一次示例（阈值仍由一小时最小间隔控制）：

```cron
*/5 * * * * cd /opt/malware-archive && /usr/bin/python3 -m malware_archive --config /etc/malware-archive.json scan
```

数据库租约能阻止本机两个 scan 重叠。生产环境还应添加结构化日志、指标、磁盘配额、
离线备份、签名清单，以及官方 advisory hook 作为确认信号。
