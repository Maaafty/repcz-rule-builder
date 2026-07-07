# Repcz Egern 国内外规则生成器

从 `Repcz/Tool` 的 `X` 分支完整镜像全部 Egern 规则，并为需要地区拆分的业务额外生成互补的 CN/Global 规则集。生成器只解析 YAML，不执行上游仓库中的脚本或工作流。

## 当前输出

`generated/Egern/Rules/` 首先包含上游全部原始规则，因此最终 Egern 配置可以只依赖本仓库。上游新增或删除规则时，下一次构建会同步反映。

可直接导入的配置位于 `Egern/Egern.yaml`。它只保留美国节点筛选组，所有规则 URL 均指向本仓库；使用前必须替换其中的机场订阅占位地址。

此外生成：

- `Bilibili_CN.yaml` / `Bilibili_Global.yaml`
- `Game_CN.yaml` / `Game_Global.yaml`
- `Microsoft_CN.yaml` / `Microsoft_Global.yaml`
- `Apple_CN.yaml` / `Apple_Global.yaml`
- `Google_CN.yaml` / `Google_Global.yaml`

`CDN.yaml` 不参与生成：CDN 的实际地区取决于 DNS 返回的边缘节点，不能根据域名可靠判断。

## 本地生成

```sh
ruby scripts/build.rb --source /path/to/Repcz-Tool
ruby -Itest test/test_build.rb
```

输出位于 `generated/Egern/Rules/`，来源提交、镜像数量和拆分数量记录在 `generated/Egern/manifest.yml`。

## 分类顺序

1. `force_cn` / `force_global` 人工覆盖。
2. `cn_sources` 中明确标记为国内的规则文件。
3. `.cn` 域名。
4. `ChinaDomain.yaml`、`ChinaIP.yaml`、`ChinaASN.yaml`。
5. 无法可靠判断的条目进入 Global。

配置入口为 `config/splits.yml`。上游出现误判时，只修改人工覆盖列表，不需要修改生成器。

## Egern 引用顺序

Egern 首次匹配后停止。必须按照 `generated/Egern/manifest.yml` 中的 `priority` 引用两个规则集：

- Bilibili：Global 在前，CN 在后，以便国际精确域名覆盖国内后缀规则。
- Game、Microsoft、Apple、Google：CN 在前，Global 在后。

示例：

```yaml
- rule_set:
    match: https://raw.githubusercontent.com/OWNER/REPO/BRANCH/generated/Egern/Rules/Bilibili_Global.yaml
    policy: Streaming
- rule_set:
    match: https://raw.githubusercontent.com/OWNER/REPO/BRANCH/generated/Egern/Rules/Bilibili_CN.yaml
    policy: DIRECT
```

## GitHub Actions

工作流每 6 小时拉取一次上游。输出没有变化时不会提交；有变化且验证通过后，使用仓库自己的 `GITHUB_TOKEN` 提交生成文件。

将项目推到 GitHub 后：

1. 把包含工作流的分支设为默认分支。
2. 在 Actions 设置中允许工作流读写仓库内容。
3. 首次手动运行 `Build split Egern rules`。

公开仓库连续 60 天没有活动时，GitHub 可能暂停定时工作流，需要手动重新启用。
