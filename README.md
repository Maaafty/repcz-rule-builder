# Egern, Mihomo, and Loon Rule Builder

为 Egern、Mihomo 和 Loon 生成语义明确、同源的国内外分流规则。项目不镜像其他配置仓库，只消费上游发布数据并转换成对应客户端的格式。

## 数据源

- v2fly/domain-list-community 官方 `dlc.dat_plain.yml`：域名与 `@cn` / `@!cn` 属性
- privacy-protection-tools/anti-AD：广告拦截
- Telegram 官方 CIDR：Telegram IP 路由
- Loyalsoldier GeoIP：客户端运行时中国 IP 判断

第三方来源和许可见 `THIRD_PARTY_NOTICES.md`。

## 输出

三端对应的逻辑规则集如下（Egern/Mihomo 使用 `.yaml`，Loon 使用 `.list`）。Loon 输出按规则类型拆分到 `generated/Loon/Rules/Domain/` 与 `generated/Loon/Rules/IP-CIDR/`：

- `Reject.yaml`
- `ChinaDomain.yaml` / `ChinaIP.yaml`
- `Bilibili_CN.yaml` / `Bilibili_Global.yaml`
- `Game_CN.yaml` / `Game_Global.yaml`
- `Apple_CN.yaml` / `Apple_Global.yaml`
- `Microsoft_CN.yaml` / `Microsoft_Global.yaml`
- `Google_CN.yaml` / `Google_Global.yaml`
- `AI.yaml` / `Streaming.yaml` / `Telegram.yaml` / `Social.yaml`
- `Manual_DNS_Domestic.yaml` / `Manual_DNS_Foreign.yaml`
- `Manual_DIRECT.yaml` / `Manual_PROXY.yaml` / `Manual_REJECT.yaml`

Egern 输出使用 `domain_set`、`domain_suffix_set`、`ip_cidr_set` 等原生字段；Mihomo 输出使用 `behavior: classical` 所需的 `payload`；Loon 输出使用可直接订阅的 `.list` 规则。Loon 的 Domain 文件只包含 `DOMAIN`、`DOMAIN-SUFFIX`、`DOMAIN-KEYWORD` 和转换后的 `URL-REGEX`，IP-CIDR 文件只包含 `GEOIP`、`IP-CIDR` 与 `IP-CIDR6`。同时包含两类规则的集合（目前是 Telegram）会生成两个独立文件，并由模板分别引用。`Manual_DNS_Domestic` 与 `Manual_DNS_Foreign` 不会生成 Loon 文件。

Loon 没有 `DOMAIN-REGEX`，构建器会把 v2fly 的域名正则转换为限定在 HTTP/HTTPS URL 主机部分的 `URL-REGEX`。因此这些少量正则无法覆盖非 HTTP 协议，其余规则保持等价。Loon 模板只配置全局 DNS，不生成插件模拟域名级 DNS 分流。

不生成通用 CDN、下载、Proxy 或 Direct 规则。未知流量由客户端的 `Final` 策略处理。

可导入配置位于：

- `Egern/Egern.yaml`
- `Mihomo/Mihomo.yaml`
- `Loon/Loon.conf`

使用前需要替换 `Proxy`/`Subscription` 中的订阅占位地址。Mihomo 和 Loon 都不会把 Egern/Surge 的 `sgmodule` 当作原生插件，因此这些模块不会写入相应模板。

## 手动规则

手动维护的规则放在 `manual/Egern/Rules/`。构建时会原样复制到 Egern 输出，并自动转换为 Mihomo classical rule-provider；路由类手动规则还会转换为 Loon 订阅规则：

- `Manual_DNS_Domestic.yaml`：强制使用国内加密 DNS
- `Manual_DNS_Foreign.yaml`：强制使用国外加密 DNS
- `Manual_DIRECT.yaml`：强制直连
- `Manual_PROXY.yaml`：强制代理
- `Manual_REJECT.yaml`：强制拦截

其中两个 `Manual_DNS_*` 文件仅用于 Egern 与 Mihomo；Loon 不生成对应规则，也不通过插件模拟 DNS 分流。

不要把这些文件留空。当前模板使用 `.invalid` 占位域名保证 rule-set 有效；添加真实规则后可以删掉对应占位。

## 本地构建

```sh
curl -L --fail -o /tmp/dlc.dat_plain.yml https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat_plain.yml
curl -L --fail -o /tmp/anti-ad-surge.txt https://raw.githubusercontent.com/privacy-protection-tools/anti-AD/master/anti-ad-surge.txt
curl -L --fail -o /tmp/telegram-cidr.txt https://core.telegram.org/resources/cidr.txt

ruby scripts/build.rb \
  --v2fly /tmp/dlc.dat_plain.yml \
  --anti-ad /tmp/anti-ad-surge.txt \
  --telegram /tmp/telegram-cidr.txt
ruby -Itest test/test_build.rb
```

构建只使用 Ruby 标准库。每次运行都会清理三个客户端的旧规则文件，来源哈希和规则数量分别记录在各自 `generated/<Client>/manifest.yml`；Loon manifest 使用 `Domain/<名称>` 和 `IP-CIDR/<名称>` 标识拆分后的文件。

## 自动更新

GitHub Actions 每天下载并校验 v2fly 发布产物，测试通过后同时更新 Egern、Mihomo 与 Loon 的 `generated/`。输出没有变化时不提交。
