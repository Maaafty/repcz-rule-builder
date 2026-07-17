# Egern and Mihomo Rule Builder

为 Egern 和 Mihomo 生成语义明确、同源的国内外分流规则。项目不镜像其他配置仓库，只消费上游发布数据并转换成对应客户端的 YAML。

## 数据源

- v2fly/domain-list-community 官方 `dlc.dat_plain.yml`：域名与 `@cn` / `@!cn` 属性
- privacy-protection-tools/anti-AD：广告拦截
- Telegram 官方 CIDR：Telegram IP 路由
- Loyalsoldier GeoIP：客户端运行时中国 IP 判断

第三方来源和许可见 `THIRD_PARTY_NOTICES.md`。

## 输出

`generated/Egern/Rules/` 和 `generated/Mihomo/Rules/` 包含同名、同数量的规则：

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

Egern 输出使用 `domain_set`、`domain_suffix_set`、`ip_cidr_set` 等原生字段；Mihomo 输出使用 `behavior: classical` 所需的 `payload`，可同时容纳域名、GEOIP 和 CIDR 规则。

不生成通用 CDN、下载、Proxy 或 Direct 规则。未知流量由客户端的 `Final` 策略处理。

可导入配置位于：

- `Egern/Egern.yaml`
- `Mihomo/Mihomo.yaml`

使用前需要替换 `Proxy`/`Subscription` 中的订阅占位地址。Mihomo 不支持 Egern/Surge 的 `sgmodule`，因此模块不会写入 Mihomo 模板。

## 手动规则

手动维护的规则放在 `manual/Egern/Rules/`。构建时会原样复制到 Egern 输出，并自动转换为 Mihomo classical rule-provider：

- `Manual_DNS_Domestic.yaml`：强制使用国内加密 DNS
- `Manual_DNS_Foreign.yaml`：强制使用国外加密 DNS
- `Manual_DIRECT.yaml`：强制直连
- `Manual_PROXY.yaml`：强制代理
- `Manual_REJECT.yaml`：强制拦截

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

构建只使用 Ruby 标准库。每次运行都会清理两个客户端的旧规则文件，来源哈希和规则数量分别记录在 `generated/Egern/manifest.yml` 和 `generated/Mihomo/manifest.yml`。

## 自动更新

GitHub Actions 每天下载并校验 v2fly 发布产物，测试通过后同时更新 Egern 与 Mihomo 的 `generated/`。输出没有变化时不提交。
