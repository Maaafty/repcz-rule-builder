#!/usr/bin/env ruby
# frozen_string_literal: true

require "digest"
require "fileutils"
require "json"
require "optparse"
require "set"
require "yaml"

module EgernRules
  TYPE_FIELDS = {
    "domain" => "domain_suffix_set",
    "full" => "domain_set",
    "keyword" => "domain_keyword_set",
    "regexp" => "domain_regex_set"
  }.freeze
  FIELD_ORDER = %w[
    domain_set domain_keyword_set domain_suffix_set domain_regex_set
    geoip_set ip_cidr_set ip_cidr6_set
  ].freeze
  MIHOMO_RULE_TYPES = {
    "domain_set" => "DOMAIN",
    "domain_keyword_set" => "DOMAIN-KEYWORD",
    "domain_suffix_set" => "DOMAIN-SUFFIX",
    "domain_regex_set" => "DOMAIN-REGEX",
    "geoip_set" => "GEOIP",
    "ip_cidr_set" => "IP-CIDR",
    "ip_cidr6_set" => "IP-CIDR6"
  }.freeze
  LOON_RULE_TYPES = {
    "domain_set" => "DOMAIN",
    "domain_keyword_set" => "DOMAIN-KEYWORD",
    "domain_suffix_set" => "DOMAIN-SUFFIX",
    "geoip_set" => "GEOIP",
    "ip_cidr_set" => "IP-CIDR",
    "ip_cidr6_set" => "IP-CIDR6"
  }.freeze
  LOON_NO_RESOLVE_FIELDS = %w[geoip_set ip_cidr_set ip_cidr6_set].freeze
  LOON_RULE_FAMILIES = {
    "Domain" => %w[domain_set domain_keyword_set domain_suffix_set domain_regex_set],
    "IP-CIDR" => %w[geoip_set ip_cidr_set ip_cidr6_set]
  }.freeze
  LOON_EXCLUDED_MANUAL_OUTPUTS = %w[Manual_DNS_Domestic Manual_DNS_Foreign].freeze
  SOURCE_URLS = {
    "v2fly" => "https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat_plain.yml",
    "anti_ad" => "https://raw.githubusercontent.com/privacy-protection-tools/anti-AD/master/anti-ad-surge.txt",
    "telegram" => "https://core.telegram.org/resources/cidr.txt"
  }.freeze

  module_function

  def load_yaml(path)
    YAML.safe_load(File.read(path), permitted_classes: [], permitted_symbols: [], aliases: false, filename: path) || {}
  rescue Psych::Exception => e
    raise "Invalid YAML #{path}: #{e.message}"
  end

  def parse_v2fly(path)
    lists = load_yaml(path).fetch("lists")
    raise "v2fly lists must be an array" unless lists.is_a?(Array)

    lists.to_h do |list|
      name = list.fetch("name")
      rules = list.fetch("rules").map { |line| parse_v2fly_rule(line) }
      raise "v2fly #{name}: declared length does not match rules" unless list.fetch("length") == rules.length

      [name, rules]
    end
  end

  def parse_v2fly_rule(line)
    parts = line.split(":")
    type = parts.shift
    tags = []
    tags.unshift(parts.pop.delete_prefix("@")) while parts.last&.start_with?("@")
    value = parts.join(":").strip
    raise "Unsupported v2fly rule type: #{type}" unless TYPE_FIELDS.key?(type)
    raise "Empty v2fly rule: #{line}" if value.empty?

    value = value.downcase unless type == "regexp"

    { "field" => TYPE_FIELDS.fetch(type), "value" => value, "tags" => Set.new(tags) }
  end

  def select_rules(lists, names, require_tags: [], exclude_tags: [])
    Array(names).flat_map do |name|
      lists.fetch(name) { raise "Missing v2fly list: #{name}" }
    end.select do |rule|
      require_tags.all? { |tag| rule["tags"].include?(tag) } &&
        exclude_tags.none? { |tag| rule["tags"].include?(tag) }
    end
  end

  def fields_from(rules)
    fields = Hash.new { |hash, key| hash[key] = Set.new }
    rules.each { |rule| fields[rule.fetch("field")] << rule.fetch("value") }
    fields
  end

  def merge_fields(*groups)
    merged = Hash.new { |hash, key| hash[key] = Set.new }
    groups.each { |group| group.each { |field, values| merged[field].merge(values) } }
    merged
  end

  def minimize_domains!(fields)
    suffixes = fields["domain_suffix_set"] || Set.new
    suffixes.delete_if do |value|
      labels = value.split(".")
      (1...labels.length).any? { |index| suffixes.include?(labels[index..].join(".")) }
    end
    (fields["domain_set"] || Set.new).delete_if do |value|
      labels = value.split(".")
      (0...labels.length).any? { |index| suffixes.include?(labels[index..].join(".")) }
    end
    fields
  end

  def parse_anti_ad(path)
    fields = Hash.new { |hash, key| hash[key] = Set.new }
    File.foreach(path, chomp: true) do |line|
      next if line.empty? || line.start_with?("#")

      type, value = line.split(",", 2)
      raise "Unsupported anti-AD rule: #{line}" unless type == "DOMAIN-SUFFIX" && value && !value.empty?

      fields["domain_suffix_set"] << value.downcase
    end
    minimize_domains!(fields)
  end

  def parse_telegram_cidr(path)
    fields = Hash.new { |hash, key| hash[key] = Set.new }
    File.read(path).split.each do |cidr|
      field = cidr.include?(":") ? "ip_cidr6_set" : "ip_cidr_set"
      fields[field] << cidr
    end
    fields
  end

  def suffix_covers?(suffix, value)
    value == suffix || value.end_with?(".#{suffix}")
  end

  def validate_split!(name, first, second)
    FIELD_ORDER.each do |field|
      overlap = (first[field] || Set.new) & (second[field] || Set.new)
      raise "#{name}: overlap in #{field}: #{overlap.first}" unless overlap.empty?
    end

    (first["domain_suffix_set"] || Set.new).each do |suffix|
      %w[domain_set domain_suffix_set].each do |field|
        covered = (second[field] || Set.new).find { |value| suffix_covers?(suffix, value) }
        raise "#{name}: #{suffix} shadows #{field}:#{covered}" if covered
      end
    end
  end

  def rule_count(fields)
    FIELD_ORDER.sum { |field| Array(fields[field]).length }
  end

  def select_fields(fields, selected_fields)
    selected_fields.to_h do |field|
      [field, fields[field]]
    end.reject { |_field, values| values.nil? || values.empty? }
  end

  def dump_rule(name, fields, sources, no_resolve: false)
    count = rule_count(fields)
    raise "#{name}: generated an empty rule set" if count.zero?

    lines = [
      "# Generated by egern-rule-builder",
      "# Sources: #{sources.join(', ')}",
      "# Rule count: #{count}",
      ""
    ]
    lines << "no_resolve: true" << "" if no_resolve
    FIELD_ORDER.each do |field|
      values = fields[field]
      next if values.nil? || values.empty?

      lines << "#{field}:"
      values.sort.each { |value| lines << "  - #{JSON.generate(value)}" }
      lines << ""
    end
    lines.join("\n").rstrip + "\n"
  end

  def dump_mihomo_rule(name, fields, sources)
    count = rule_count(fields)
    raise "#{name}: generated an empty rule set" if count.zero?

    lines = [
      "# Generated by egern-rule-builder",
      "# Sources: #{sources.join(', ')}",
      "# Rule count: #{count}",
      "",
      "payload:"
    ]
    FIELD_ORDER.each do |field|
      Array(fields[field]).sort.each do |value|
        lines << "  - #{JSON.generate("#{MIHOMO_RULE_TYPES.fetch(field)},#{value}")}"
      end
    end
    lines.join("\n") + "\n"
  end

  def loon_url_regex(value)
    suffix_aware = value.start_with?("(^|\\.)")
    anchored = value.start_with?("^")
    body = value.delete_prefix("(^|\\.)").delete_prefix("^").delete_suffix("$")
    prefix = suffix_aware || !anchored ? "(?:[^/?#]+\\.)*" : ""
    "^https?://#{prefix}(?:#{body})(?::[0-9]+)?(?:[/?#]|$)"
  end

  def dump_loon_rule(name, fields, sources, no_resolve: false)
    count = rule_count(fields)
    raise "#{name}: generated an empty rule set" if count.zero?

    lines = [
      "# Generated by egern-rule-builder",
      "# Sources: #{sources.join(', ')}",
      "# Rule count: #{count}",
      ""
    ]
    FIELD_ORDER.each do |field|
      Array(fields[field]).sort.each do |value|
        if field == "domain_regex_set"
          regex = loon_url_regex(value)
          raise "#{name}: Loon URL regex contains an unsupported comma" if regex.include?(",")

          lines << "URL-REGEX,#{regex}"
        else
          rule = "#{LOON_RULE_TYPES.fetch(field)},#{value}"
          rule += ",no-resolve" if no_resolve && LOON_NO_RESOLVE_FIELDS.include?(field)
          lines << rule
        end
      end
    end
    lines.join("\n") + "\n"
  end

  def sha256(path)
    Digest::SHA256.file(path).hexdigest
  end

  def copy_manual_rules(manual_path, output, reserved_names)
    return {} unless manual_path && Dir.exist?(manual_path)

    Dir[File.join(manual_path, "*.yaml")].sort.to_h do |path|
      name = File.basename(path, ".yaml")
      raise "#{name}: manual rule set conflicts with generated output" if reserved_names.include?(name)

      data = load_yaml(path)
      count = rule_count(data)
      raise "#{name}: manual rule set is empty" if count.zero?

      FileUtils.cp(path, File.join(output, "#{name}.yaml"))
      [name, count]
    end
  end

  def write_mihomo_rules(output:, generated_outputs:, output_sources:, manual_path:, reserved_names:)
    FileUtils.mkdir_p(output)
    Dir[File.join(output, "*.yaml")].each { |path| FileUtils.rm_f(path) }

    generated_outputs.each do |name, fields|
      File.write(
        File.join(output, "#{name}.yaml"),
        dump_mihomo_rule(name, fields, output_sources.fetch(name))
      )
    end

    return unless manual_path && Dir.exist?(manual_path)

    Dir[File.join(manual_path, "*.yaml")].sort.each do |path|
      name = File.basename(path, ".yaml")
      raise "#{name}: manual rule set conflicts with generated output" if reserved_names.include?(name)

      fields = load_yaml(path)
      raise "#{name}: manual rule set is empty" if rule_count(fields).zero?

      File.write(
        File.join(output, "#{name}.yaml"),
        dump_mihomo_rule(name, fields, ["manual:Egern/Rules/#{File.basename(path)}"])
      )
    end
  end

  def write_loon_rule_files(output, name, fields, sources, no_resolve: false)
    LOON_RULE_FAMILIES.each_with_object({}) do |(family, family_fields), counts|
      selected = select_fields(fields, family_fields)
      next if rule_count(selected).zero?

      family_output = File.join(output, family)
      FileUtils.mkdir_p(family_output)
      File.write(
        File.join(family_output, "#{name}.list"),
        dump_loon_rule(name, selected, sources, no_resolve: no_resolve)
      )
      counts["#{family}/#{name}"] = rule_count(selected)
    end
  end

  def write_loon_rules(output:, generated_outputs:, output_sources:, manual_path:, reserved_names:, no_resolve_outputs:)
    FileUtils.mkdir_p(output)
    Dir[File.join(output, "**", "*.list")].each { |path| FileUtils.rm_f(path) }

    loon_outputs = generated_outputs.each_with_object({}) do |(name, fields), counts|
      counts.merge!(
        write_loon_rule_files(
          output,
          name,
          fields,
          output_sources.fetch(name),
          no_resolve: no_resolve_outputs.include?(name)
        )
      )
    end

    if manual_path && Dir.exist?(manual_path)
      Dir[File.join(manual_path, "*.yaml")].sort.each do |path|
        name = File.basename(path, ".yaml")
        raise "#{name}: manual rule set conflicts with generated output" if reserved_names.include?(name)
        next if LOON_EXCLUDED_MANUAL_OUTPUTS.include?(name)

        fields = load_yaml(path)
        raise "#{name}: manual rule set is empty" if rule_count(fields).zero?

        loon_outputs.merge!(
          write_loon_rule_files(
            output,
            name,
            fields,
            ["manual:Egern/Rules/#{File.basename(path)}"]
          )
        )
      end
    end

    plugin_path = File.join(File.dirname(output), "Plugins", "DNS.plugin")
    FileUtils.rm_f(plugin_path)
    loon_outputs
  end

  def build(
    config_path:, v2fly_path:, anti_ad_path:, telegram_path:, output:, manual_path: nil,
    mihomo_output: nil, loon_output: nil
  )
    config = load_yaml(config_path)
    lists = parse_v2fly(v2fly_path)
    outputs = {}
    output_sources = {}

    config.fetch("splits").each do |name, settings|
      source = settings.fetch("list")
      global_source = settings.fetch("global_list", source)
      common_excludes = Array(settings["exclude_tags"])
      cn_rules = select_rules(
        lists,
        source,
        require_tags: Array(settings.dig("cn", "require_tags")),
        exclude_tags: common_excludes + Array(settings.dig("cn", "exclude_tags"))
      )
      global_rules = select_rules(
        lists,
        global_source,
        require_tags: Array(settings.dig("global", "require_tags")),
        exclude_tags: common_excludes + Array(settings.dig("global", "exclude_tags"))
      )

      if settings["cn_extra_list"]
        cn_rules += select_rules(
          lists,
          settings.fetch("cn_extra_list"),
          require_tags: Array(settings["cn_extra_require_tags"]),
          exclude_tags: common_excludes
        )
      end

      cn = minimize_domains!(fields_from(cn_rules))
      global = minimize_domains!(fields_from(global_rules))
      priority = settings.fetch("priority")
      raise "#{name}: priority must be cn or global" unless %w[cn global].include?(priority)

      first, second = priority == "cn" ? [cn, global] : [global, cn]
      validate_split!(name, first, second)
      outputs["#{name}_CN"] = cn
      outputs["#{name}_Global"] = global
      output_sources["#{name}_CN"] = ["v2fly:#{source}"]
      output_sources["#{name}_CN"] << "v2fly:#{settings.fetch('cn_extra_list')}" if settings["cn_extra_list"]
      output_sources["#{name}_Global"] = ["v2fly:#{global_source}"]
    end

    config.fetch("groups").each do |name, settings|
      rules = select_rules(
        lists,
        settings.fetch("lists"),
        require_tags: Array(settings["require_tags"]),
        exclude_tags: Array(settings["exclude_tags"])
      )
      outputs[name] = minimize_domains!(fields_from(rules))
      output_sources[name] = settings.fetch("lists").map { |source| "v2fly:#{source}" }
    end

    outputs["Telegram"] = merge_fields(
      outputs.fetch("Telegram"),
      parse_telegram_cidr(telegram_path)
    )
    output_sources["Telegram"] << "telegram:cidr"

    cn_groups = config.fetch("china_domain_extra_outputs").map { |name| outputs.fetch(name) }
    outputs["ChinaDomain"] = minimize_domains!(merge_fields(
      fields_from(select_rules(lists, config.fetch("china_domain_list"))),
      *cn_groups
    ))
    output_sources["ChinaDomain"] = ["v2fly:#{config.fetch('china_domain_list')}"] +
      config.fetch("china_domain_extra_outputs").map { |name| "generated:#{name}" }

    outputs["ChinaIP"] = { "geoip_set" => Set["CN"] }
    output_sources["ChinaIP"] = ["Loyalsoldier:Country-without-asn.mmdb"]
    outputs["Reject"] = parse_anti_ad(anti_ad_path)
    output_sources["Reject"] = ["anti-AD:anti-ad-surge.txt"]
    no_resolve_outputs = Array(config["no_resolve_outputs"])
    unknown_no_resolve = no_resolve_outputs - outputs.keys
    raise "Unknown no_resolve outputs: #{unknown_no_resolve.join(', ')}" unless unknown_no_resolve.empty?

    FileUtils.mkdir_p(output)
    Dir[File.join(output, "*.yaml")].each { |path| FileUtils.rm_f(path) }
    outputs.each do |name, fields|
      File.write(
        File.join(output, "#{name}.yaml"),
        dump_rule(name, fields, output_sources.fetch(name), no_resolve: no_resolve_outputs.include?(name))
      )
    end
    manual_outputs = copy_manual_rules(manual_path, output, outputs.keys)

    manifest = {
      "sources" => {
        "v2fly" => { "url" => SOURCE_URLS.fetch("v2fly"), "sha256" => sha256(v2fly_path) },
        "anti_ad" => { "url" => SOURCE_URLS.fetch("anti_ad"), "sha256" => sha256(anti_ad_path) },
        "telegram" => { "url" => SOURCE_URLS.fetch("telegram"), "sha256" => sha256(telegram_path) }
      },
      "outputs" => outputs.transform_values { |fields| rule_count(fields) }.merge(manual_outputs)
    }
    File.write(File.join(File.dirname(output), "manifest.yml"), YAML.dump(manifest))

    if mihomo_output
      write_mihomo_rules(
        output: mihomo_output,
        generated_outputs: outputs,
        output_sources: output_sources,
        manual_path: manual_path,
        reserved_names: outputs.keys
      )
      File.write(File.join(File.dirname(mihomo_output), "manifest.yml"), YAML.dump(manifest))
    end
    if loon_output
      loon_outputs = write_loon_rules(
        output: loon_output,
        generated_outputs: outputs,
        output_sources: output_sources,
        manual_path: manual_path,
        reserved_names: outputs.keys,
        no_resolve_outputs: no_resolve_outputs
      )
      loon_manifest = manifest.merge("outputs" => loon_outputs)
      File.write(File.join(File.dirname(loon_output), "manifest.yml"), YAML.dump(loon_manifest))
    end
    manifest
  end
end

if $PROGRAM_NAME == __FILE__
  begin
    root = File.expand_path("..", __dir__)
    options = {
      config_path: File.join(root, "config", "splits.yml"),
      manual_path: File.join(root, "manual", "Egern", "Rules"),
      output: File.join(root, "generated", "Egern", "Rules"),
      mihomo_output: File.join(root, "generated", "Mihomo", "Rules"),
      loon_output: File.join(root, "generated", "Loon", "Rules")
    }
    OptionParser.new do |parser|
      parser.banner = "Usage: ruby scripts/build.rb --v2fly FILE --anti-ad FILE --telegram FILE"
      parser.on("--v2fly FILE", "v2fly dlc.dat_plain.yml") { |value| options[:v2fly_path] = value }
      parser.on("--anti-ad FILE", "anti-AD Surge list") { |value| options[:anti_ad_path] = value }
      parser.on("--telegram FILE", "Telegram official CIDR list") { |value| options[:telegram_path] = value }
      parser.on("--config FILE", "Build configuration") { |value| options[:config_path] = value }
      parser.on("--manual PATH", "Manual rules directory") { |value| options[:manual_path] = value }
      parser.on("--output PATH", "Generated rules directory") { |value| options[:output] = value }
      parser.on("--mihomo-output PATH", "Generated Mihomo rules directory") { |value| options[:mihomo_output] = value }
      parser.on("--loon-output PATH", "Generated Loon rules directory") { |value| options[:loon_output] = value }
    end.parse!
    %i[v2fly_path anti_ad_path telegram_path].each { |key| abort "--#{key.to_s.tr('_', '-')} is required" unless options[key] }

    manifest = EgernRules.build(**options)
    manifest.fetch("outputs").each { |name, count| puts "#{name}: #{count}" }
  rescue KeyError, ArgumentError, RuntimeError => e
    warn e.message
    exit 1
  end
end
