#!/usr/bin/env ruby
# frozen_string_literal: true

require "fileutils"
require "ipaddr"
require "json"
require "open3"
require "optparse"
require "set"
require "yaml"

module SplitRules
  FIELD_ORDER = %w[
    domain_set domain_keyword_set domain_suffix_set domain_regex_set
    domain_wildcard_set geoip_set ip_cidr_set ip_cidr6_set url_regex_set
    asn_set user_agent_set ssid_set bssid_set cellular_set protocol_set
    dest_port_set and_set or_set not_set
  ].freeze
  DOMAIN_FIELDS = %w[domain_set domain_suffix_set].freeze
  IP_FIELDS = %w[ip_cidr_set ip_cidr6_set].freeze

  module_function

  def load_yaml(path)
    YAML.safe_load(
      File.read(path),
      permitted_classes: [],
      permitted_symbols: [],
      aliases: false,
      filename: path
    ) || {}
  rescue Psych::Exception => e
    raise "Invalid YAML #{path}: #{e.message}"
  end

  def load_rule(path)
    raw = load_yaml(path)
    raise "Rule must be a mapping: #{path}" unless raw.is_a?(Hash)

    unknown = raw.keys - FIELD_ORDER - ["no_resolve"]
    raise "Unsupported fields in #{path}: #{unknown.join(', ')}" unless unknown.empty?

    fields = {}
    FIELD_ORDER.each do |field|
      next unless raw.key?(field)

      values = raw[field]
      raise "#{path}: #{field} must be an array" unless values.is_a?(Array)
      raise "#{path}: #{field} only supports strings" unless values.all? { |value| value.is_a?(String) }

      fields[field] = Set.new(values.map { |value| value.strip }.reject(&:empty?))
    end
    { "no_resolve" => raw["no_resolve"] == true, "fields" => fields }
  end

  def domain_ancestors(value)
    labels = value.downcase.split(".")
    (0...labels.length).map { |index| labels[index..-1].join(".") }
  end

  def domain_in_reference?(field, value, reference)
    exact = reference["domain_set"] || Set.new
    suffixes = reference["domain_suffix_set"] || Set.new
    normalized = value.downcase

    case field
    when "domain_set"
      exact.include?(normalized) || domain_ancestors(normalized).any? { |suffix| suffixes.include?(suffix) }
    when "domain_suffix_set"
      domain_ancestors(normalized).any? { |suffix| suffixes.include?(suffix) }
    else
      false
    end
  end

  def pattern_match?(value, pattern)
    value = value.downcase
    pattern = pattern.downcase
    return value == pattern.delete_prefix("*.") || value.end_with?(pattern.delete_prefix("*")) if pattern.start_with?("*.")

    File.fnmatch?(pattern, value, File::FNM_CASEFOLD | File::FNM_EXTGLOB)
  end

  def forced?(value, patterns)
    Array(patterns).any? { |pattern| pattern_match?(value, pattern) }
  end

  def ip_in_china?(value, china_ranges)
    candidate = IPAddr.new(value)
    china_ranges.any? do |range|
      range.ipv4? == candidate.ipv4? &&
        range.include?(candidate.to_range.first) &&
        range.include?(candidate.to_range.last)
    end
  rescue IPAddr::InvalidAddressError
    raise "Invalid IP/CIDR: #{value}"
  end

  def classify(field, value, settings, context, forced_cn_source)
    force_cn = forced?(value, settings["force_cn"])
    force_global = forced?(value, settings["force_global"])
    raise "#{value} is forced to both CN and Global" if force_cn && force_global
    return :cn if force_cn
    return :global if force_global
    return :cn if forced_cn_source

    if DOMAIN_FIELDS.include?(field)
      return :cn if settings["match_cn_tld"] && (value.downcase == "cn" || value.downcase.end_with?(".cn"))
      return :cn if settings["match_china_domain"] && domain_in_reference?(field, value, context[:china_domains])
    elsif IP_FIELDS.include?(field)
      return :cn if ip_in_china?(value, context[:china_ranges])
    elsif field == "asn_set"
      return :cn if context[:china_asns].include?(value.downcase)
    elsif field == "geoip_set"
      return :cn if value.casecmp("CN").zero?
    end

    :global
  end

  def merge_sources(rules_dir, sources)
    merged = Hash.new { |hash, key| hash[key] = Set.new }
    no_resolve = false
    sources.each do |source|
      rule = load_rule(File.join(rules_dir, source))
      no_resolve ||= rule["no_resolve"]
      rule["fields"].each { |field, values| merged[field].merge(values) }
    end
    [merged, no_resolve]
  end

  def source_membership(rules_dir, sources)
    entries = Set.new
    Array(sources).each do |source|
      load_rule(File.join(rules_dir, source))["fields"].each do |field, values|
        values.each { |value| entries << [field, value] }
      end
    end
    entries
  end

  def suffix_covers?(suffix, value)
    value == suffix || value.end_with?(".#{suffix}")
  end

  def unsafe_shadowing(first, second)
    suffixes = first["domain_suffix_set"] || Set.new
    return [] if suffixes.empty?

    shadowed = []
    %w[domain_set domain_suffix_set].each do |field|
      (second[field] || Set.new).each do |value|
        covering = suffixes.find { |suffix| suffix_covers?(suffix.downcase, value.downcase) }
        shadowed << "#{covering} shadows #{field}:#{value}" if covering
      end
    end
    shadowed
  end

  def normalize_shadowing!(first, second, locked_second, target)
    loop do
      moved = false
      suffixes = first["domain_suffix_set"] || Set.new
      %w[domain_set domain_suffix_set].each do |field|
        (second[field] || Set.new).to_a.each do |value|
          covering = suffixes.find { |suffix| suffix_covers?(suffix.downcase, value.downcase) }
          next unless covering

          if locked_second.include?([field, value])
            raise "#{target}: priority rule #{covering} shadows forced #{field}:#{value}"
          end
          second[field].delete(value)
          first[field] << value
          moved = true
        end
      end
      break unless moved
    end
  end

  def validate_partition!(target, original, cn, global, priority)
    FIELD_ORDER.each do |field|
      source = original[field] || Set.new
      cn_values = cn[field] || Set.new
      global_values = global[field] || Set.new
      overlap = cn_values & global_values
      raise "#{target}: exact overlap in #{field}: #{overlap.first}" unless overlap.empty?
      raise "#{target}: entries were lost or added in #{field}" unless (cn_values | global_values) == source
    end

    first, second = priority == "global" ? [global, cn] : [cn, global]
    shadowed = unsafe_shadowing(first, second)
    return if shadowed.empty?

    raise "#{target}: #{priority.upcase}-first order shadows later rules: #{shadowed.first(5).join('; ')}"
  end

  def dump_rule(target, region, sources, upstream_sha, no_resolve, fields)
    count = fields.values.sum(&:length)
    lines = [
      "# Generated by repcz-rule-builder",
      "# Target: #{target} #{region}",
      "# Upstream commit: #{upstream_sha}",
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

  def git_sha(source)
    output, status = Open3.capture2("git", "-C", source, "rev-parse", "HEAD")
    status.success? ? output.strip : "local"
  end

  def build(config_path:, source:, output:, upstream_sha: nil)
    config = load_yaml(config_path)
    rules_dir = File.join(source, config.fetch("upstream").fetch("rules_path"))
    raise "Rules directory not found: #{rules_dir}" unless Dir.exist?(rules_dir)

    references = config.fetch("references")
    china_domains = load_rule(File.join(rules_dir, references.fetch("china_domain")))["fields"].transform_values do |values|
      Set.new(values.map(&:downcase))
    end
    china_ip_rule = load_rule(File.join(rules_dir, references.fetch("china_ip")))
    china_ranges = IP_FIELDS.flat_map { |field| (china_ip_rule["fields"][field] || Set.new).map { |value| IPAddr.new(value) } }
    china_asns = Set.new((load_rule(File.join(rules_dir, references.fetch("china_asn")))["fields"]["asn_set"] || Set.new).map(&:downcase))
    context = { china_domains: china_domains, china_ranges: china_ranges, china_asns: china_asns }
    upstream_sha ||= git_sha(source)

    FileUtils.mkdir_p(output)
    Dir[File.join(output, "*.yaml")].each { |path| FileUtils.rm_f(path) }
    upstream_rules = Dir[File.join(rules_dir, "*.yaml")].sort
    upstream_rules.each { |path| FileUtils.cp(path, File.join(output, File.basename(path))) }
    manifest_targets = {}

    config.fetch("targets").each do |target, settings|
      sources = settings.fetch("sources")
      original, no_resolve = merge_sources(rules_dir, sources)
      forced_cn_entries = source_membership(rules_dir, settings["cn_sources"])
      cn = Hash.new { |hash, key| hash[key] = Set.new }
      global = Hash.new { |hash, key| hash[key] = Set.new }
      locked_cn = Set.new
      locked_global = Set.new

      original.each do |field, values|
        values.each do |value|
          entry = [field, value]
          force_cn = forced?(value, settings["force_cn"])
          force_global = forced?(value, settings["force_global"])
          region = classify(field, value, settings, context, forced_cn_entries.include?(entry))
          (region == :cn ? cn : global)[field] << value
          locked_cn << entry if force_cn || forced_cn_entries.include?(entry)
          locked_global << entry if force_global
        end
      end

      priority = settings.fetch("priority", "cn")
      raise "#{target}: priority must be cn or global" unless %w[cn global].include?(priority)
      if priority == "global"
        normalize_shadowing!(global, cn, locked_cn, target)
      else
        normalize_shadowing!(cn, global, locked_global, target)
      end
      validate_partition!(target, original, cn, global, priority)

      File.write(File.join(output, "#{target}_CN.yaml"), dump_rule(target, "CN", sources, upstream_sha, no_resolve, cn))
      File.write(File.join(output, "#{target}_Global.yaml"), dump_rule(target, "Global", sources, upstream_sha, no_resolve, global))
      manifest_targets[target] = {
        "sources" => sources,
        "priority" => priority,
        "cn_rules" => cn.values.sum(&:length),
        "global_rules" => global.values.sum(&:length)
      }
    end

    manifest = {
      "upstream" => config.fetch("upstream").merge(
        "commit" => upstream_sha,
        "mirrored_rules" => upstream_rules.length
      ),
      "targets" => manifest_targets
    }
    File.write(File.join(File.dirname(output), "manifest.yml"), YAML.dump(manifest))
    manifest
  end
end

if $PROGRAM_NAME == __FILE__
  begin
    root = File.expand_path("..", __dir__)
    options = {
      config_path: File.join(root, "config", "splits.yml"),
      output: File.join(root, "generated", "Egern", "Rules")
    }
    OptionParser.new do |parser|
      parser.banner = "Usage: ruby scripts/build.rb --source PATH [options]"
      parser.on("--source PATH", "Repcz/Tool checkout") { |value| options[:source] = value }
      parser.on("--config PATH", "Split configuration") { |value| options[:config_path] = value }
      parser.on("--output PATH", "Generated rules directory") { |value| options[:output] = value }
      parser.on("--sha SHA", "Upstream commit for generated headers") { |value| options[:upstream_sha] = value }
    end.parse!
    abort "--source is required" unless options[:source]

    manifest = SplitRules.build(**options)
    puts "Mirrored rules: #{manifest.dig('upstream', 'mirrored_rules')}"
    manifest.fetch("targets").each do |target, stats|
      puts "#{target}: CN=#{stats['cn_rules']} Global=#{stats['global_rules']} priority=#{stats['priority']}"
    end
  rescue KeyError, ArgumentError, RuntimeError => e
    warn e.message
    exit 1
  end
end
