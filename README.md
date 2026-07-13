# Egern Rule Builder

为 Egern 生成语义明确的国内外分流规则。项目不镜像其他配置仓库，只消费上游发布数据并转换成 Egern YAML。

## 数据源

- v2fly/domain-list-community 官方 `dlc.dat_plain.yml`：域名与 `@cn` / `@!cn` 属性
- privacy-protection-tools/anti-AD：广告拦截
- Telegram 官方 CIDR：Telegram IP 路由
- Loyalsoldier GeoIP：Egern 运行时中国 IP 判断

第三方来源和许可见 `THIRD_PARTY_NOTICES.md`。

## 输出

`generated/Egern/Rules/` 只包含：

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

不生成通用 CDN、下载、Proxy 或 Direct 规则。未知流量由 Egern 的 `Final` 策略处理。

可导入配置位于 `Egern/Egern.yaml`。使用前需要替换 `Proxy` 中的订阅占位地址。

## 手动规则

手动维护的规则放在 `manual/Egern/Rules/`，构建时会复制到 `generated/Egern/Rules/`：

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

构建只使用 Ruby 标准库。每次运行都会清理旧规则文件，来源哈希和规则数量记录在 `generated/Egern/manifest.yml`。

## 自动更新

GitHub Actions 每天下载并校验 v2fly 发布产物，测试通过后更新 `generated/`。输出没有变化时不提交。
