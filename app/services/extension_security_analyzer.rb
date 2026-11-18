# Rates an extension from its manifest, then adds the AI context analysis
# and records the tweet. The rule data (levels, rules, permission ratings,
# sensitive sites) lives in ExtensionAnalyzerData; match patterns are parsed
# by MatchPattern.
#
# Rating model: every finding has a level (Critical, High, Medium or Low).
# The overall rating is the highest level found, or Minimal when nothing is
# found. Nothing is counted: many Low findings stay Low.
#
# The rules run on a freshly extracted manifest (top-level symbol keys, raw
# with string keys) and on a stored one (everything deep-symbolized), and on
# any junk an extension can ship: they never raise on bad input.
class ExtensionSecurityAnalyzer
  include ExtensionAnalyzerData

  # Bump when the rules or their texts change, so RuleRerating picks up
  # every stored scan again. Stored on the overall finding as :rules_version.
  # Findings written before the version existed carry none (version 1).
  RULES_VERSION = 2

  OVERALL_TITLE_PREFIX = "Overall Risk: ".freeze

  # Content Security Policy keys of a Manifest V3 object. A Manifest V2
  # string applies to the extension's own pages, like "extension_pages".
  CSP_EXTENSION_PAGES = "extension_pages".freeze
  CSP_KEYS = %w[extension_pages sandbox isolated_world].freeze

  # A match pattern found in the manifest and where it was written.
  Site = Struct.new(:pattern, :path, :source, keyword_init: true)

  # The rule findings for a manifest (overall finding first), without the AI
  # step or the tweet. Used by RuleRerating.
  def self.rule_findings(manifest)
    new(manifest).rule_findings
  end

  def initialize(manifest, extension_details = nil, extension_name = nil, extension_id = nil, previous_findings: nil, ai_client: :default)
    @manifest = manifest
    @extension_details = extension_details
    @extension_name = extension_name
    @extension_id = extension_id
    @previous_findings = previous_findings
    @ai_client = ai_client
    @security_findings = []
  end

  def analyze
    return [] unless @manifest

    @security_findings = rule_findings.map(&:dup)
    analyze_with_claude
    tweet_results
    @security_findings
  end

  # The overall finding followed by every rule finding.
  def rule_findings
    @rule_findings ||= begin
      @findings = []
      @data = @manifest.is_a?(Hash) ? @manifest : {}
      analyze_permissions
      analyze_site_access
      analyze_combinations
      analyze_optional
      analyze_csp
      analyze_manifest_version
      [overall_finding] + @findings
    end
  end

  private

  # --- reading the manifest -------------------------------------------------

  def lookup(hash, key)
    return nil unless hash.is_a?(Hash)

    hash.key?(key.to_s) ? hash[key.to_s] : hash[key.to_sym]
  end

  def raw
    @raw ||= lookup(@data, :raw).then { |r| r.is_a?(Hash) ? r : {} }
  end

  # A manifest key as written (raw), falling back to the extracted copy for
  # manifests stored without raw. Evidence paths always use the key name.
  def read(key)
    raw.key?(key.to_s) || raw.key?(key.to_sym) ? lookup(raw, key) : lookup(@data, key)
  end

  # [entry, index] for each string entry of a list key; [] when not a list.
  def string_entries(key)
    list = read(key)
    return [] unless list.is_a?(Array)

    list.each_with_index.select { |entry, _| entry.is_a?(String) }
  end

  def manifest_version
    value = read(:manifest_version)
    case value
    when Integer then value
    when Float then value.to_i if value == value.to_i
    when String then Integer(value.strip, 10, exception: false)
    end
  end

  # Manifest V2 rules (match patterns inside "permissions") apply unless the
  # manifest says version 3 or later: the conservative reading for junk.
  def legacy?
    version = manifest_version
    version.nil? || version < 3
  end

  # Required API permissions: name => indexes in "permissions".
  def required_permissions
    @required_permissions ||= api_permissions(:permissions)
  end

  def api_permissions(key)
    string_entries(key).each_with_object({}) do |(entry, index), names|
      next if legacy? && MatchPattern.parse(entry).valid?

      (names[entry] ||= []) << index
    end
  end

  def required_sites
    @required_sites ||= begin
      sites = string_entries(:host_permissions).map { |p, i| site(p, ["host_permissions", i], :host_permissions) }
      if legacy?
        sites += string_entries(:permissions).map { |p, i| site(p, ["permissions", i], :permissions) }
      end
      sites.select { |s| s.pattern.valid? }
    end
  end

  def content_script_sites
    @content_script_sites ||= begin
      scripts = read(:content_scripts)
      scripts = [] unless scripts.is_a?(Array)
      scripts.each_with_index.flat_map do |script, i|
        matches = lookup(script, :matches)
        next [] unless matches.is_a?(Array)

        matches.each_with_index.filter_map do |pattern, j|
          next unless pattern.is_a?(String)

          s = site(pattern, ["content_scripts", i, "matches", j], :content_scripts)
          s if s.pattern.valid?
        end
      end
    end
  end

  def optional_sites
    @optional_sites ||= begin
      sites = string_entries(:optional_host_permissions).map { |p, i| site(p, ["optional_host_permissions", i], :optional_host_permissions) }
      if legacy?
        sites += string_entries(:optional_permissions).map { |p, i| site(p, ["optional_permissions", i], :optional_permissions) }
      end
      sites.select { |s| s.pattern.valid? }
    end
  end

  def site(pattern, path, source)
    Site.new(pattern: MatchPattern.parse(pattern), path: path, source: source)
  end

  # --- rules ----------------------------------------------------------------

  def analyze_permissions
    required_permissions.each do |name, indexes|
      entry = PERMISSIONS[name]
      next unless entry

      add_finding(entry.level, "#{entry.level}-Risk Permission: #{name}",
                  "It asks for the #{name} permission, which lets it #{lower_first(entry.allows)}. " \
                  "#{entry.why || 'This is a routine permission with little risk on its own.'}",
                  rule: "permission", evidence: indexes.map { |i| ["permissions", i] })
    end
  end

  def analyze_site_access
    all_sites = required_sites.select { |s| s.pattern.all_sites? }
    if all_sites.any?
      add_finding("High", "Access to All Websites",
                  "It can read and change every website you visit, including sites where you are signed in, " \
                  "such as email and banking.#{suffix_note(all_sites)}",
                  rule: "host.all_sites", evidence: all_sites.map(&:path))
    end

    scripts_everywhere = content_script_sites.select { |s| s.pattern.all_sites? }
    if scripts_everywhere.any?
      add_finding("High", "Scripts Run on All Websites",
                  "Its scripts run automatically in every website you open, where they can read and change the page, " \
                  "including what you type.#{suffix_note(scripts_everywhere)}",
                  rule: "content_script.all_sites", evidence: scripts_everywhere.map(&:path))
    end

    granted = required_sites + content_script_sites
    files = granted.select { |s| s.pattern.file? }
    if files.any?
      add_finding("Low", "Access to Local Files",
                  "It asks to read files on your computer (file:// addresses). Chrome only allows this if you turn on " \
                  "\"Allow access to file URLs\" for the extension.",
                  rule: "host.file", evidence: files.map(&:path))
    end

    sensitive = sensitive_matches(granted)
    if sensitive.any?
      add_finding("Medium", "Access to Sensitive Sites",
                  "It asks for access to sites where people bank, pay, shop or sign in: #{sensitive_names(sensitive)}. " \
                  "On these sites it could read what you see and act as you.",
                  rule: "host.sensitive", evidence: sensitive.map { |s, _| s.path })
    end
  end

  # Critical: required access to all websites together with permissions
  # that turn it into control over accounts or traffic everywhere.
  def analyze_combinations
    all_sites = required_sites.select { |s| s.pattern.all_sites? }
    return if all_sites.empty?

    texts = {
      "combination.all_sites_cookies" => [
        "All Websites Plus Cookies",
        "It has access to every website and the cookies permission. Together they let it read the cookies that keep " \
        "you signed in on any site and use them to act as you, for example to take over your accounts."
      ],
      "combination.all_sites_web_request_blocking" => [
        "All Websites Plus Blocking Web Requests",
        "It has access to every website and the webRequest and webRequestBlocking permissions. Together they let it " \
        "watch, block and change the traffic of every site while it happens."
      ]
    }
    CRITICAL_COMBINATIONS.each do |rule, names|
      next unless names.all? { |n| required_permissions.key?(n) }

      title, description = texts.fetch(rule)
      evidence = all_sites.map(&:path) + names.flat_map { |n| required_permissions[n].map { |i| ["permissions", i] } }
      add_finding("Critical", title, description, rule: rule, evidence: evidence)
    end
  end

  # Items it can ask for later. Chrome asks the user first, so each is rated
  # one level below the same item at install. Items also requested at install
  # are covered there and not repeated.
  def analyze_optional
    api_permissions(:optional_permissions).each do |name, indexes|
      entry = PERMISSIONS[name]
      next if entry.nil? || required_permissions.key?(name)

      add_finding(optional_level(entry.level), "Optional Permission: #{name}",
                  "It can ask for the #{name} permission later; Chrome asks you before granting it. If you agree, " \
                  "it lets it #{lower_first(entry.allows)}.#{entry.why ? " #{entry.why}" : ''}",
                  rule: "optional.permission", evidence: indexes.map { |i| ["optional_permissions", i] })
    end

    already_all = required_sites.any? { |s| s.pattern.all_sites? }
    all_sites = optional_sites.select { |s| s.pattern.all_sites? }
    if all_sites.any? && !already_all
      add_finding(optional_level("High"), "Optional Access to All Websites",
                  "It can ask for access to every website later; Chrome asks you before granting it. If you agree, it can " \
                  "read and change every website you visit, including sites where you are signed in.#{suffix_note(all_sites)}",
                  rule: "optional.host.all_sites", evidence: all_sites.map(&:path))
    end

    granted = required_sites + content_script_sites
    files = optional_sites.select { |s| s.pattern.file? }
    if files.any? && granted.none? { |s| s.pattern.file? }
      add_finding(optional_level("Low"), "Optional Access to Local Files",
                  "It can ask to read files on your computer (file:// addresses) later; Chrome asks you before granting it, " \
                  "and file access also has to be turned on for the extension.",
                  rule: "optional.host.file", evidence: files.map(&:path))
    end

    known = sensitive_matches(granted).map { |s, _| s.pattern.registrable_domain }
    sensitive = sensitive_matches(optional_sites).reject { |s, _| known.include?(s.pattern.registrable_domain) }
    if sensitive.any?
      add_finding(optional_level("Medium"), "Optional Access to Sensitive Sites",
                  "It can ask for access to sites where people bank, pay, shop or sign in later; Chrome asks you before " \
                  "granting it: #{sensitive_names(sensitive)}.",
                  rule: "optional.host.sensitive", evidence: sensitive.map { |s, _| s.path })
    end
  end

  # Only the policy for the extension's own pages counts: sandboxed pages
  # have no access to extension APIs, and using eval there is what Chrome
  # recommends, so a sandbox policy produces no finding.
  def analyze_csp
    eval_paths = []
    wasm_paths = []
    csp_policies.each do |key, policy, path|
      next unless key == CSP_EXTENSION_PAGES

      sources = script_sources(policy)
      eval_paths << path if sources.include?("'unsafe-eval'")
      wasm_paths << path if sources.include?("'wasm-unsafe-eval'")
    end

    if eval_paths.any?
      add_finding("High", "Unsafe JavaScript Evaluation",
                  "Its Content Security Policy for its own pages allows 'unsafe-eval', so its code can turn text into code " \
                  "and run it (eval and similar functions). That makes it easier to run code that was never reviewed, " \
                  "such as code downloaded later.",
                  rule: "csp.unsafe_eval", evidence: eval_paths)
    end
    if wasm_paths.any?
      add_finding("Low", "WebAssembly Allowed",
                  "Its Content Security Policy allows 'wasm-unsafe-eval', which lets its pages run WebAssembly. " \
                  "This is the standard way to use WebAssembly in Manifest V3 and is not a concern on its own.",
                  rule: "csp.wasm_unsafe_eval", evidence: wasm_paths)
    end
  end

  def analyze_manifest_version
    version = manifest_version
    return unless version && version < 3

    add_finding("Low", "Older Manifest Version",
                "It uses Manifest V#{version}, an older format with fewer restrictions than Manifest V3: for example, it " \
                "can use code hosted on other servers and block web requests. Chrome is phasing Manifest V2 out.",
                rule: "manifest.v2", evidence: [["manifest_version"]])
  end

  # --- helpers --------------------------------------------------------------

  # [[key, policy, evidence path]]. The scanner stores an object policy as
  # "key: value" strings; those are read back when raw is missing.
  def csp_policies
    value = raw.key?("content_security_policy") || raw.key?(:content_security_policy) ? lookup(raw, :content_security_policy) : nil
    case value
    when String
      [[CSP_EXTENSION_PAGES, value, ["content_security_policy"]]]
    when Hash
      value.filter_map do |key, policy|
        [key.to_s, policy, ["content_security_policy", key.to_s]] if policy.is_a?(String)
      end
    when nil
      stored = lookup(@data, :content_security_policy)
      stored = [stored] if stored.is_a?(String)
      return [] unless stored.is_a?(Array)

      stored.grep(String).map do |policy|
        key, rest = policy.split(": ", 2)
        if rest && CSP_KEYS.include?(key)
          [key, rest, ["content_security_policy", key]]
        else
          [CSP_EXTENSION_PAGES, policy, ["content_security_policy"]]
        end
      end
    else
      []
    end
  end

  # The sources that govern eval: script-src, or default-src when there is
  # no script-src. The first occurrence of a directive wins, as in browsers.
  def script_sources(policy)
    directives = {}
    policy.split(";").each do |directive|
      name, *sources = directive.strip.split(/\s+/)
      next if name.nil? || name.empty?

      directives[name.downcase] ||= sources.map(&:downcase)
    end
    directives["script-src"] || directives["default-src"] || []
  end

  # [[site, category]] for named sites on the sensitive list. All-site and
  # file patterns have their own rules and are never "sensitive sites".
  def sensitive_matches(sites)
    sites.filter_map do |s|
      next if s.pattern.all_sites? || s.pattern.file?

      domain = s.pattern.registrable_domain
      category = domain && sensitive_category(domain, s.pattern.domain_label)
      [s, category] if category
    end
  end

  def sensitive_names(matches)
    matches.map { |s, category| "#{s.pattern.registrable_domain} (#{category})" }.uniq.join(", ")
  end

  def suffix_note(sites)
    wide = sites.map(&:pattern).select(&:public_suffix_wildcard?).uniq(&:to_s)
    return "" if wide.empty?

    wide.map { |p| " The pattern \"#{p}\" covers every site ending in .#{p.domain}, so it counts as all websites." }.join
  end

  def lower_first(text)
    text.empty? ? text : text[0].downcase + text[1..]
  end

  # A stored rule finding. Besides the three display fields it carries:
  #   rule:     the stable id of the rule that produced it (see
  #             ExtensionAnalyzerData::RULES); the page groups by it.
  #   evidence: the places in manifest.json the finding points at, as a list
  #             of paths into the manifest as written (the stored :raw), each
  #             a list of object keys (strings) and array indexes (integers):
  #             [["permissions", 3], ["content_scripts", 0, "matches", 1]].
  # The Manifest tab annotates those lines with the finding. Findings stored
  # before these fields existed have neither.
  def add_finding(severity, title, description, rule: nil, evidence: [])
    finding = { severity: severity, title: title, description: description }
    finding[:rule] = rule if rule
    finding[:evidence] = evidence.uniq if evidence.any?
    @findings << finding
  end

  # The highest level found; Minimal when nothing was found. Carries the
  # rules version so stored scans can be re-rated when the rules change.
  def overall_finding
    level = highest_level(@findings.map { |f| f[:severity] }) || "Minimal"
    description = if @findings.empty?
      "No rule found anything to flag, so the rating is Minimal."
    else
      counts = LEVELS.filter_map do |l|
        n = @findings.count { |f| f[:severity] == l }
        "#{n} #{l}" if n.positive?
      end
      noun = @findings.size == 1 ? "finding" : "findings"
      "The rating is the highest level among #{@findings.size} rule #{noun} (#{counts.join(', ')})."
    end
    { severity: level, title: "#{OVERALL_TITLE_PREFIX}#{level}", description: description, rules_version: RULES_VERSION }
  end

  def analyze_with_claude
    finding = AiContextAnalysis.new(
      manifest: @manifest,
      extension_details: @extension_details,
      extension_name: @extension_name,
      findings: @security_findings,
      previous_findings: @previous_findings,
      client: @ai_client
    ).call
    @security_findings << finding if finding
  rescue StandardError => e
    # AiContextAnalysis does not raise; this keeps the rule findings even if it ever does.
    Rails.logger.error "AI analysis failed for #{@extension_id}: #{e.class}: #{e.message}"
  end

  def tweet_results
    tweet_text = format_tweet_text
    Rails.logger.info "#{tweet_text}"
    TwitterClient.new.post_tweet(tweet_text)
  rescue => e
    Rails.logger.error "Failed to tweet scan results: #{e.message}"
  end

  def format_tweet_text
    ai_analysis = @security_findings.find { |f| f[:severity] == "Info" && f[:title] == "AI Context Analysis" }

    risk_level = if ai_analysis&.[](:description)&.start_with?("Risk Level:")
      ai_analysis[:description].split("\n").first.split("Risk Level:").last&.strip
    else
      "N/A"
    end

    overall_risk = @security_findings.find { |f| f[:title]&.downcase&.include?('overall risk') }&.[](:severity) || "N/A"

    combined_risk = if risk_level == overall_risk
      "Risk: #{risk_level}"
    else
      "Risk: #{risk_level} / #{overall_risk}"
    end

    [
      @extension_name.presence || "Unknown Extension",
      "#{(@extension_details[:rating].present? && @extension_details[:rating_count].present?) ?
        "#{@extension_details[:rating]} ★ (#{@extension_details[:rating_count]})" : "? ★"}, #{@extension_details[:size].presence || "?KiB"}",
      combined_risk,
      "https://crxaminer.tech/scan/#{@extension_id}"
    ].join("\n")
  rescue StandardError => e
    Rails.logger.error "Error formatting tweet text: #{e.message}"
    "Scan complete! https://crxaminer.tech/scan/#{@extension_id}"
  end

end
