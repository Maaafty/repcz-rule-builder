# frozen_string_literal: true

require "fileutils"
require "minitest/autorun"
require "tmpdir"
require "yaml"
require_relative "../scripts/build"

class BuildTest < Minitest::Test
  def setup
    @tmp = Dir.mktmpdir
    @rules = File.join(@tmp, "Egern", "Rules")
    FileUtils.mkdir_p(@rules)
    write_rule("ChinaDomain.yaml", "domain_suffix_set" => ["cn.example"])
    write_rule("ChinaIP.yaml", "ip_cidr_set" => ["10.0.0.0/8"])
    write_rule("ChinaASN.yaml", "asn_set" => ["AS123"])
    write_rule("Service.yaml", {
      "domain_set" => ["local.cn.example", "intl.cn.example", "global.example"],
      "domain_suffix_set" => ["cn.example", "world.example"],
      "ip_cidr_set" => ["10.1.0.0/16", "192.0.2.0/24"]
    })
  end

  def teardown
    FileUtils.remove_entry(@tmp)
  end

  def test_builds_lossless_partition_with_specific_global_override
    config = write_config("global")
    output = File.join(@tmp, "generated", "Egern", "Rules")
    manifest = SplitRules.build(config_path: config, source: @tmp, output: output, upstream_sha: "abc123")

    cn = YAML.safe_load(File.read(File.join(output, "Service_CN.yaml")), aliases: false)
    global = YAML.safe_load(File.read(File.join(output, "Service_Global.yaml")), aliases: false)
    assert File.exist?(File.join(output, "Service.yaml")), "upstream rule was not mirrored"
    assert_includes cn.fetch("domain_set"), "local.cn.example"
    assert_includes global.fetch("domain_set"), "intl.cn.example"
    assert_includes cn.fetch("ip_cidr_set"), "10.1.0.0/16"
    assert_equal 3, manifest.dig("targets", "Service", "cn_rules")
    assert_equal 4, manifest.dig("targets", "Service", "global_rules")
    assert_equal 4, manifest.dig("upstream", "mirrored_rules")
  end

  def test_rejects_priority_that_shadows_specific_override
    config = write_config("cn")
    error = assert_raises(RuntimeError) do
      SplitRules.build(config_path: config, source: @tmp, output: File.join(@tmp, "out"), upstream_sha: "abc123")
    end
    assert_match(/shadows forced/, error.message)
  end

  private

  def write_rule(name, data)
    File.write(File.join(@rules, name), YAML.dump(data))
  end

  def write_config(priority)
    config = {
      "upstream" => { "rules_path" => "Egern/Rules" },
      "references" => {
        "china_domain" => "ChinaDomain.yaml",
        "china_ip" => "ChinaIP.yaml",
        "china_asn" => "ChinaASN.yaml"
      },
      "targets" => {
        "Service" => {
          "sources" => ["Service.yaml"],
          "priority" => priority,
          "match_china_domain" => true,
          "match_cn_tld" => true,
          "force_global" => ["intl.cn.example"]
        }
      }
    }
    path = File.join(@tmp, "config.yml")
    File.write(path, YAML.dump(config))
    path
  end
end
