# frozen_string_literal: true

require "fileutils"
require "minitest/autorun"
require "tmpdir"
require "yaml"
require_relative "../scripts/build"

class BuildTest < Minitest::Test
  def setup
    @tmp = Dir.mktmpdir
    @v2fly = File.join(@tmp, "dlc.yml")
    @anti_ad = File.join(@tmp, "anti-ad.txt")
    @telegram = File.join(@tmp, "telegram.txt")
    @config = File.join(@tmp, "config.yml")
    @output = File.join(@tmp, "generated", "Egern", "Rules")
    @mihomo_output = File.join(@tmp, "generated", "Mihomo", "Rules")
    @loon_output = File.join(@tmp, "generated", "Loon", "Rules")
    FileUtils.mkdir_p(@output)
    FileUtils.mkdir_p(@mihomo_output)
    FileUtils.mkdir_p(File.join(@loon_output, "Domain"))
    FileUtils.mkdir_p(File.join(@tmp, "generated", "Loon", "Plugins"))
    File.write(File.join(@output, "OldMirror.yaml"), "domain_set:\n  - old.example\n")
    File.write(File.join(@mihomo_output, "OldMirror.yaml"), "payload:\n  - DOMAIN,old.example\n")
    File.write(File.join(@loon_output, "Domain", "OldMirror.list"), "DOMAIN,old.example\n")
    File.write(File.join(@loon_output, "OldLegacy.list"), "DOMAIN,old.example\n")
    File.write(File.join(@tmp, "generated", "Loon", "Plugins", "DNS.plugin"), "stale\n")

    write_v2fly
    File.write(@anti_ad, "# anti-AD\nDOMAIN-SUFFIX,ads.example\nDOMAIN-SUFFIX,sub.ads.example\n")
    File.write(@telegram, "91.108.4.0/22\n2001:b28:f23d::/48\n")
    File.write(@config, YAML.dump(config))
  end

  def teardown
    FileUtils.remove_entry(@tmp)
  end

  def test_builds_region_aware_minimal_rules
    manifest = EgernRules.build(
      config_path: @config,
      v2fly_path: @v2fly,
      anti_ad_path: @anti_ad,
      telegram_path: @telegram,
      output: @output,
      mihomo_output: @mihomo_output,
      loon_output: @loon_output
    )

    bilibili_cn = rule("Bilibili_CN")
    bilibili_global = rule("Bilibili_Global")
    streaming = rule("Streaming")
    game_cn = rule("Game_CN")
    game_global = rule("Game_Global")
    china = rule("ChinaDomain")

    assert_includes bilibili_cn.fetch("domain_suffix_set"), "bilibili.com"
    assert_includes bilibili_global.fetch("domain_suffix_set"), "bilibili.tv"
    refute_includes streaming.fetch("domain_suffix_set"), "youtube.cn"
    assert_includes game_cn.fetch("domain_suffix_set"), "steam.cn"
    assert_includes game_global.fetch("domain_suffix_set"), "steam.com"
    assert_includes china.fetch("domain_suffix_set"), "apple.cn"
    assert_equal ["CN"], rule("ChinaIP").fetch("geoip_set")
    assert_equal ["ads.example"], rule("Reject").fetch("domain_suffix_set")
    assert_includes rule("Telegram").fetch("ip_cidr6_set"), "2001:b28:f23d::/48"
    assert_equal true, rule("Telegram").fetch("no_resolve")
    assert_includes mihomo_rule("Bilibili_CN").fetch("payload"), "DOMAIN-SUFFIX,bilibili.com"
    assert_includes mihomo_rule("Reject").fetch("payload"), "DOMAIN-SUFFIX,ads.example"
    assert_includes mihomo_rule("Telegram").fetch("payload"), "IP-CIDR6,2001:b28:f23d::/48"
    assert_includes mihomo_rule("ChinaIP").fetch("payload"), "GEOIP,CN"
    assert_includes loon_rule("Bilibili_CN"), "DOMAIN-SUFFIX,bilibili.com"
    assert_includes loon_rule("Reject"), "DOMAIN-SUFFIX,ads.example"
    assert_includes loon_rule("Telegram"), "DOMAIN-SUFFIX,telegram.org"
    assert_includes loon_rule("Telegram", "IP-CIDR"), "IP-CIDR6,2001:b28:f23d::/48,no-resolve"
    assert_includes loon_rule("ChinaIP", "IP-CIDR"), "GEOIP,CN"
    assert_includes loon_rule("Streaming"),
      "URL-REGEX,^https?://(?:video\\S+\\.example\\.com)(?::[0-9]+)?(?:[/?#]|$)"
    assert_includes loon_rule("Streaming"), "DOMAIN,asset0.example.com"
    assert_includes loon_rule("Streaming"), "DOMAIN,asset9.example.com"
    assert_includes loon_rule("Streaming"), "DOMAIN-SUFFIX,cdn1.example.net"
    assert_includes loon_rule("Streaming"), "DOMAIN-SUFFIX,cdn2.example.net"
    refute File.exist?(File.join(@output, "OldMirror.yaml"))
    refute File.exist?(File.join(@mihomo_output, "OldMirror.yaml"))
    refute File.exist?(File.join(@loon_output, "Domain", "OldMirror.list"))
    refute File.exist?(File.join(@loon_output, "OldLegacy.list"))
    refute File.exist?(File.join(@tmp, "generated", "Loon", "Plugins", "DNS.plugin"))
    assert File.exist?(File.join(@tmp, "generated", "Mihomo", "manifest.yml"))
    assert File.exist?(File.join(@tmp, "generated", "Loon", "manifest.yml"))
    loon_manifest = YAML.safe_load(
      File.read(File.join(@tmp, "generated", "Loon", "manifest.yml")), aliases: false
    )
    assert_equal 1, loon_manifest.fetch("outputs").fetch("Domain/Telegram")
    assert_equal 2, loon_manifest.fetch("outputs").fetch("IP-CIDR/Telegram")
    assert_equal 21, loon_manifest.fetch("outputs").fetch("Domain/Streaming")
    assert loon_rule("Telegram").all? { |line| line.match?(/\A(?:DOMAIN|URL-REGEX)/) }
    assert loon_rule("Telegram", "IP-CIDR").all? { |line| line.match?(/\A(?:GEOIP|IP-CIDR)/) }
    refute File.exist?(File.join(@loon_output, "IP-CIDR", "Bilibili_CN.list"))
    assert_equal 17, manifest.fetch("outputs").length
  end

  def test_copies_manual_rules
    manual = File.join(@tmp, "manual", "Egern", "Rules")
    FileUtils.mkdir_p(manual)
    File.write(File.join(manual, "Manual_DIRECT.yaml"), "domain_set:\n  - manual.example\n")
    File.write(File.join(manual, "Manual_DNS_Domestic.yaml"), "domain_set:\n  - dns.example\n")

    manifest = EgernRules.build(
      config_path: @config,
      v2fly_path: @v2fly,
      anti_ad_path: @anti_ad,
      telegram_path: @telegram,
      output: @output,
      manual_path: manual,
      mihomo_output: @mihomo_output,
      loon_output: @loon_output
    )

    assert_equal ["manual.example"], rule("Manual_DIRECT").fetch("domain_set")
    assert_equal ["dns.example"], rule("Manual_DNS_Domestic").fetch("domain_set")
    assert_equal ["DOMAIN,manual.example"], mihomo_rule("Manual_DIRECT").fetch("payload")
    assert_equal ["DOMAIN,dns.example"], mihomo_rule("Manual_DNS_Domestic").fetch("payload")
    assert_equal ["DOMAIN,manual.example"], loon_rule("Manual_DIRECT")
    refute File.exist?(File.join(@loon_output, "Domain", "Manual_DNS_Domestic.list"))
    assert_equal 1, manifest.fetch("outputs").fetch("Manual_DIRECT")
  end

  def test_preserves_regex_case_while_normalizing_domains
    regex = EgernRules.parse_v2fly_rule("regexp:^chatgpt-\\S+-\\d+\\.example\\.com$")
    domain = EgernRules.parse_v2fly_rule("domain:Example.COM")

    assert_equal "^chatgpt-\\S+-\\d+\\.example\\.com$", regex.fetch("value")
    assert_equal "example.com", domain.fetch("value")
  end

  def test_expands_only_finite_loon_domain_regexes
    exact = EgernRules.expand_loon_domain_regex("^asset\\d\\.example\\.com$")
    suffix = EgernRules.expand_loon_domain_regex(".+\\.awsdns-cn-[0-9][a-e0-9]\\.cn$")

    assert_equal "DOMAIN", exact.fetch("rule_type")
    assert_equal 10, exact.fetch("values").length
    assert_includes exact.fetch("values"), "asset9.example.com"
    assert_equal "DOMAIN-SUFFIX", suffix.fetch("rule_type")
    assert_equal 150, suffix.fetch("values").length
    assert_includes suffix.fetch("values"), "awsdns-cn-0a.cn"
    assert_nil EgernRules.expand_loon_domain_regex("^asset\\d+\\.example\\.com$")
    assert_nil EgernRules.expand_loon_domain_regex("^asset[0-9][0-9][0-9][0-9]\\.example\\.com$")
  end

  def test_rejects_empty_manual_rules
    manual = File.join(@tmp, "manual", "Egern", "Rules")
    FileUtils.mkdir_p(manual)
    File.write(File.join(manual, "Manual_DIRECT.yaml"), "# empty\n")

    error = assert_raises(RuntimeError) do
      EgernRules.build(
        config_path: @config,
        v2fly_path: @v2fly,
        anti_ad_path: @anti_ad,
        telegram_path: @telegram,
        output: @output,
        manual_path: manual
      )
    end
    assert_match(/manual rule set is empty/, error.message)
  end

  def test_rejects_a_priority_rule_that_shadows_the_other_region
    first = { "domain_suffix_set" => Set["example.com"] }
    second = { "domain_set" => Set["global.example.com"] }
    error = assert_raises(RuntimeError) { EgernRules.validate_split!("Example", first, second) }
    assert_match(/shadows/, error.message)
  end

  def test_egern_config_references_every_generated_rule_once
    root = File.expand_path("..", __dir__)
    config = YAML.safe_load(File.read(File.join(root, "Egern", "Egern.yaml")), aliases: false)
    rule_references = config.fetch("rules").map do |rule|
      item = rule["rule_set"]
      File.basename(item["match"], ".yaml") if item
    end.compact
    dns_references = config.fetch("dns").fetch("forward").map do |rule|
      item = rule["proxy_rule_set"]
      File.basename(item["match"], ".yaml") if item
    end.compact
    referenced = (rule_references + dns_references).uniq
    generated = Dir[File.join(root, "generated", "Egern", "Rules", "*.yaml")].map do |path|
      File.basename(path, ".yaml")
    end

    assert_equal generated.sort, referenced.sort
    assert_equal rule_references.uniq, rule_references
    assert_equal %w[
      Manual_REJECT Reject Manual_DIRECT Bilibili_Global Bilibili_CN Game_CN Apple_CN Microsoft_CN Google_CN
      AI Streaming Game_Global Telegram Social Apple_Global Microsoft_Global
      Google_Global Manual_PROXY ChinaDomain ChinaIP
    ], rule_references
    assert_includes dns_references, "Manual_DNS_Domestic"
    assert_includes dns_references, "Manual_DNS_Foreign"
  end

  def test_mihomo_config_references_every_generated_rule
    root = File.expand_path("..", __dir__)
    config = YAML.safe_load(File.read(File.join(root, "Mihomo", "Mihomo.yaml")), aliases: false)
    providers = config.fetch("rule-providers")
    generated = Dir[File.join(root, "generated", "Egern", "Rules", "*.yaml")].map do |path|
      File.basename(path, ".yaml")
    end

    rule_references = config.fetch("rules").each_with_object([]) do |rule, references|
      parts = rule.split(",")
      references << parts[1] if parts.first == "RULE-SET"
    end
    dns_references = config.fetch("dns").fetch("nameserver-policy").keys.each_with_object([]) do |selector, references|
      references << selector.delete_prefix("rule-set:") if selector.start_with?("rule-set:")
    end

    assert_equal generated.sort, providers.keys.sort
    assert_equal generated.sort, (rule_references + dns_references).uniq.sort
    assert_equal rule_references.uniq, rule_references
    assert_equal %w[
      Manual_REJECT Reject Manual_DIRECT Bilibili_Global Bilibili_CN Game_CN Apple_CN Microsoft_CN Google_CN
      AI Streaming Game_Global Telegram Social Apple_Global Microsoft_Global
      Google_Global Manual_PROXY ChinaDomain ChinaIP
    ], rule_references
    providers.each do |name, provider|
      assert_equal "classical", provider.fetch("behavior"), name
      assert_equal "yaml", provider.fetch("format"), name
      assert_match %r{/generated/Mihomo/Rules/#{Regexp.escape(name)}\.yaml\z}, provider.fetch("url"), name
    end
    assert_equal "AND,((NETWORK,UDP),(DST-PORT,443)),REJECT", config.fetch("rules").first
  end

  def test_loon_config_references_every_routing_rule
    root = File.expand_path("..", __dir__)
    config = File.read(File.join(root, "Loon", "Loon.conf"))
    generated = Dir[File.join(root, "generated", "Egern", "Rules", "*.yaml")].map do |path|
      File.basename(path, ".yaml")
    end
    remote_rules = section_lines(config, "Remote Rule")
    rule_references = remote_rules.map do |line|
      line.split("/generated/Loon/Rules/", 2).last.split(",", 2).first.delete_suffix(".list")
    end

    assert_equal %w[
      Domain/Manual_REJECT Domain/Reject Domain/Manual_DIRECT Domain/Bilibili_Global Domain/Bilibili_CN
      Domain/Game_CN Domain/Apple_CN Domain/Microsoft_CN Domain/Google_CN Domain/AI Domain/Streaming
      Domain/Game_Global Domain/Telegram IP-CIDR/Telegram Domain/Social Domain/Apple_Global
      Domain/Microsoft_Global Domain/Google_Global Domain/Manual_PROXY Domain/ChinaDomain IP-CIDR/ChinaIP
    ], rule_references
    generated_loon = Dir[File.join(root, "generated", "Loon", "Rules", "**", "*.list")].map do |path|
      path.delete_prefix(File.join(root, "generated", "Loon", "Rules") + "/").delete_suffix(".list")
    end
    assert_equal generated_loon.sort, rule_references.sort
    egern_counts = YAML.safe_load(
      File.read(File.join(root, "generated", "Egern", "manifest.yml")), aliases: false
    ).fetch("outputs")
    loon_counts = YAML.safe_load(
      File.read(File.join(root, "generated", "Loon", "manifest.yml")), aliases: false
    ).fetch("outputs").each_with_object(Hash.new(0)) do |(path, count), counts|
      counts[path.split("/", 2).last] += count
    end
    expected_loon_counts = Dir[File.join(root, "generated", "Egern", "Rules", "*.yaml")]
      .each_with_object({}) do |path, counts|
        name = File.basename(path, ".yaml")
        next if %w[Manual_DNS_Domestic Manual_DNS_Foreign].include?(name)

        fields = YAML.safe_load(File.read(path), aliases: false)
        counts[name] = EgernRules::LOON_RULE_FAMILIES.values.sum do |family_fields|
          selected = EgernRules.select_fields(fields, family_fields)
          EgernRules.loon_rule_lines(selected, no_resolve: fields["no_resolve"] == true).length
        end
      end
    assert_equal expected_loon_counts, loon_counts
    referenced_names = rule_references.map { |reference| reference.split("/", 2).last }.uniq
    assert_equal generated.sort, (referenced_names + %w[Manual_DNS_Domestic Manual_DNS_Foreign]).sort
    assert_equal %w[Telegram], rule_references.group_by { |reference| reference.split("/", 2).last }
      .select { |_name, references| references.length > 1 }.keys
    assert_equal remote_rules.length, remote_rules.map { |line| line[/tag=([^,]+)/, 1] }.uniq.length
    assert_includes section_lines(config, "General"), "disable-udp-ports = 443"
    assert_includes section_lines(config, "General"), "domain-reject-mode = Request"
    assert_includes section_lines(config, "General"), "wifi-access-socks5-port = 6153"
    refute_includes config, "[Plugin]"
    assert_equal %w[Proxy Streaming AI Game Telegram Social Apple Microsoft Google Final],
      section_lines(config, "Proxy Group").map { |line| line.split("=", 2).first.strip }
  end

  private

  def section_lines(config, section)
    active = false
    config.lines(chomp: true).each_with_object([]) do |line, lines|
      if line.start_with?("[")
        active = line == "[#{section}]"
      elsif active && !line.empty? && !line.start_with?("#")
        lines << line
      end
    end
  end

  def rule(name)
    YAML.safe_load(File.read(File.join(@output, "#{name}.yaml")), aliases: false)
  end

  def mihomo_rule(name)
    YAML.safe_load(File.read(File.join(@mihomo_output, "#{name}.yaml")), aliases: false)
  end

  def loon_rule(name, family = "Domain")
    File.readlines(File.join(@loon_output, family, "#{name}.list"), chomp: true).reject do |line|
      line.empty? || line.start_with?("#")
    end
  end

  def write_v2fly
    lists = {
      "bilibili" => ["domain:bilibili.com", "domain:bilibili.tv:@!cn"],
      "category-games-cn" => ["domain:game.cn"],
      "category-games-!cn" => ["domain:steam.com", "domain:steam.cn:@cn"],
      "apple" => ["domain:apple.com", "domain:apple.cn:@cn"],
      "microsoft" => ["domain:microsoft.com", "domain:microsoft.cn:@cn"],
      "google" => ["domain:google.com", "domain:google.cn:@cn"],
      "category-ai-!cn" => ["domain:openai.com"],
      "youtube" => [
        "domain:youtube.com",
        "domain:youtube.cn:@cn",
        "regexp:^video\\S+\\.example\\.com$",
        "regexp:^asset\\d\\.example\\.com$",
        "regexp:(^|\\.)cdn[1-2]\\.example\\.net$"
      ],
      "netflix" => ["domain:netflix.com"],
      "disney" => ["domain:disneyplus.com"],
      "hbo" => ["domain:max.com"],
      "spotify" => ["domain:spotify.com"],
      "bahamut" => ["domain:gamer.com.tw"],
      "tiktok" => ["domain:tiktok.com"],
      "primevideo" => ["domain:primevideo.com"],
      "telegram" => ["domain:telegram.org"],
      "facebook" => ["domain:facebook.com"],
      "instagram" => ["domain:instagram.com"],
      "twitter" => ["domain:x.com"],
      "geolocation-cn" => ["domain:cn.example"]
    }.map do |name, rules|
      { "name" => name, "length" => rules.length, "rules" => rules }
    end
    File.write(@v2fly, YAML.dump("lists" => lists))
  end

  def config
    {
      "splits" => {
        "Bilibili" => split("bilibili", "global", ["!cn"], ["!cn"]),
        "Game" => {
          "list" => "category-games-cn",
          "global_list" => "category-games-!cn",
          "cn_extra_list" => "category-games-!cn",
          "cn_extra_require_tags" => ["cn"],
          "priority" => "cn",
          "cn" => { "exclude_tags" => ["!cn"] },
          "global" => { "exclude_tags" => ["cn"] }
        },
        "Apple" => corporate_split("apple"),
        "Microsoft" => corporate_split("microsoft"),
        "Google" => corporate_split("google")
      },
      "groups" => {
        "AI" => group(["category-ai-!cn"]),
        "Streaming" => group(%w[youtube netflix disney hbo spotify bahamut tiktok primevideo]),
        "Telegram" => group(["telegram"]),
        "Social" => group(%w[facebook instagram twitter])
      },
      "china_domain_list" => "geolocation-cn",
      "china_domain_extra_outputs" => %w[Bilibili_CN Game_CN Apple_CN Microsoft_CN Google_CN],
      "no_resolve_outputs" => ["Telegram"]
    }
  end

  def split(list, priority, cn_excludes, global_requires)
    {
      "list" => list,
      "priority" => priority,
      "cn" => { "exclude_tags" => cn_excludes },
      "global" => { "require_tags" => global_requires }
    }
  end

  def corporate_split(list)
    {
      "list" => list,
      "priority" => "cn",
      "cn" => { "require_tags" => ["cn"] },
      "global" => { "exclude_tags" => ["cn"] }
    }
  end

  def group(lists)
    { "lists" => lists, "exclude_tags" => %w[cn ads] }
  end
end
