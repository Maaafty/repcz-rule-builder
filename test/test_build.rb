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
    FileUtils.mkdir_p(@output)
    File.write(File.join(@output, "OldMirror.yaml"), "domain_set:\n  - old.example\n")

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
      output: @output
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
    refute File.exist?(File.join(@output, "OldMirror.yaml"))
    assert_equal 17, manifest.fetch("outputs").length
  end

  def test_copies_manual_rules
    manual = File.join(@tmp, "manual", "Egern", "Rules")
    FileUtils.mkdir_p(manual)
    File.write(File.join(manual, "Manual_DIRECT.yaml"), "domain_set:\n  - manual.example\n")

    manifest = EgernRules.build(
      config_path: @config,
      v2fly_path: @v2fly,
      anti_ad_path: @anti_ad,
      telegram_path: @telegram,
      output: @output,
      manual_path: manual
    )

    assert_equal ["manual.example"], rule("Manual_DIRECT").fetch("domain_set")
    assert_equal 1, manifest.fetch("outputs").fetch("Manual_DIRECT")
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

  private

  def rule(name)
    YAML.safe_load(File.read(File.join(@output, "#{name}.yaml")), aliases: false)
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
      "youtube" => ["domain:youtube.com", "domain:youtube.cn:@cn"],
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
