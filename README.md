# Malware archive detector

一个保守的软件包下架检测、原始制品隔离归档与实时监控站。

它做三件事：

1. 使用 npm `_changes` 与 PyPI 官方 journal 游标流增量建立版本快照，也可手工登记精确版本；
2. 将 npm 最近七天的变更切成 sequence batch，先入队最新批次，再按实际版本发布时间计算 coverage；
3. 从 OpenSSF 官方 npm、PyPI、RubyGems、crates.io、Go、Maven 与 NuGet 倒序修改索引持续导入 `MAL-*`，最新更新优先并逐步回填历史记录；
4. 周期性检查候选版本在官方 registry 中是否仍然存在；
5. 首次发现版本消失时立即并发查询全部镜像，抢救原始归档并标记为待确认；
6. 独立地连续确认官方缺失，达到阈值后才把已捕获制品晋级为最终归档，并在受 Cloudflare Access 保护的网站提供筛选、下载和静态源码预览。

采集器**不会**调用 `npm install`、`pip install`，不会解压、导入或执行包内代码。源码预览由
一个断网 Docker 容器限额解包，只接受普通文件并拒绝链接、特殊文件、路径穿越和压缩炸弹。详见
[架构文档](docs/architecture.md)。

## 快速开始

要求 Python 3.11+，运行时只使用标准库。

```bash
cp config.example.json config.json
python -m malware_archive --config config.json init
python -m malware_archive --config config.json observe npm left-pad 1.3.0
python -m malware_archive --config config.json scan --dry-run
python -m malware_archive --config config.json discover
python -m malware_archive --config config.json discover-pypi
python -m malware_archive --config config.json serve --allow-local-preview
```

确认配置和检测结果后，去掉 `--dry-run` 才会下载。`daemon` 会持续消费增量变更流并按
配置周期运行扫描；单次 scan 带数据库租约，避免两个任务重叠。

查看状态：

```bash
python -m malware_archive --config config.json list
python -m malware_archive --config config.json events --limit 50
```

运行离线测试：

```bash
python -m unittest discover -s tests -v
```

> “从官方源消失”并不能单独证明一个包是恶意软件。本项目将这类对象标记为
> `suspected_takedown`，保留每次探测证据，供后续结合官方安全公告或人工审核确认。
> 镜像捕获发生在第一次缺失时，不等待这个确认流程。

## 远程部署边界

生产配置位于 `deploy/config.remote.json`，状态和制品保存在
`/srv/data-island-alert`。Web 服务固定监听 `127.0.0.1:8787`，不允许改成公网地址；
`alert.dataisland.org` 只应通过 Cloudflare Tunnel 到达，并由现有的 Zero Trust
`Malware Package Browser` 应用和 `OwnCode` 策略保护。

制品下载路由不会把 TGZ、sdist、GEM、CRATE、Go ZIP、JAR 或 NUPKG 当网页展示：响应固定为 `application/octet-stream`、
`Content-Disposition: attachment` 和 `X-Content-Type-Options: nosniff`。没有官方
SHA-256/SHA-512 的镜像样本会进入 `archived_unverified`，不会伪装成已验证证据。

源码查看器运行于 Compose 中独立的 `viewer` 容器：`network_mode: none`，只读挂载原始
归档，预览输出写到 `/srv/data-island-alert-views`，Web 再以只读方式挂载该目录。
OpenSSF 情报通过 OSV API 查询，但只有 `MAL-*` 标识会设置 malware 标签；普通 CVE/GHSA
不会被误当成恶意包。七个生态的官方 `modified_id.csv` 每小时同步一次，历史报告以最新优先方式回填；
withdrawn 或改写后的报告会重新计算其版本标签。
