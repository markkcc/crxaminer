# Rates an extension from its manifest, then adds the AI context analysis
# and records the tweet. The rule data (levels, rules, permission ratings,
# sensitive sites) lives in ExtensionAnalyzerData; match patterns are parsed
# by MatchPattern.
#
# Rating model: every finding has a level (Critical, High, Medium or Low),
# which is its capability tier (ScanRating::ACCESS_TIERS). The access rating
# is the highest level found, or Minimal when nothing is found. Nothing is
# counted: many Low findings stay Low. The AI check cannot change it.
#
# The stored list is: the overall finding (the combined verdict of access
# and trust, see ScanRating and #overall_finding), the rule findings most
# severe first, then the AI finding when there is one.
#
# The rules run on a freshly extracted manifest (top-level symbol keys, raw
# with string keys) and on a stored one (everything deep-symbolized), and on
# any junk an extension can ship: they never raise on bad input.
class ExtensionSecurityAnalyzer
  include ExtensionAnalyzerData

  # Bump when the rules or their texts change, so RuleRerating picks up
  # every stored scan again. Stored on the overall finding as :rules_version.
  # Findings written before the version existed carry none (version 1).
  #   4: capability tiers; the overall finding carries the combined verdict
  #      (severity = overall level, plus access, trust and headline).
  RULES_VERSION = 4

  OVERALL_TITLE_PREFIX = "Overall Risk: ".freeze

  # Content Security Policy keys of a Manifest V3 object. A Manifest V2
  # string applies to the extension's own pages, like "extension_pages".
  CSP_EXTENSION_PAGES = "extension_pages".freeze
  CSP_KEYS = %w[extension_pages sandbox isolated_world].freeze

  # A match pattern found in the manifest and where it was written.
  Site = Struct.new(:pattern, :path, :source, keyword_init: true)

  # The overall finding followed by the rule findings for a manifest alone,
  # rated as if there were no listing data and no AI check. No AI call, no
  # tweet.
  def self.rule_findings(manifest)
    new(manifest).rule_findings
  end

  # The whole stored list rebuilt from stored data, with the current rules:
  # the overall finding (rated from the access level, the stored listing
  # details and the first stored AI finding), the rule findings, then every
  # stored AI finding exactly as given (old-format ones included; they add
  # nothing to trust). No AI call, no tweet. Used by RuleRerating and
  # AiVerdictBackfill.
  def self.rated_findings(manifest, extension_details: nil, ai_findings: [])
    ai_findings = Array(ai_findings).select { |f| f.is_a?(Hash) && ScanPage::FindingGroups.ai?(f) }
    new(manifest, extension_details).rated_findings(ai_findings)
  end

  # What the statistics count for one manifest, read exactly as the rules
  # read it, so the dashboard and the scan pages agree:
  #   manifest_version             2, 3, ... or nil when it is not a number
  #   permissions                  the API permissions it asks for at install
  #                                (Manifest V2 match patterns left out)
  #   all_sites_host_access        does a required host permission cover all sites?
  #   all_sites_content_scripts    does a content script run on all sites?
  # No findings are built. Never raises on junk.
  ManifestSummary = Struct.new(:manifest_version, :permissions, :all_sites_host_access, :all_sites_content_scripts,
                               keyword_init: true)

  def self.manifest_summary(manifest)
    new(manifest).manifest_summary
  end

  TWEET_LIMIT = 280
  TWEET_FIELD_LIMIT = 20

  # The post for X: the name, the store rating line, the overall level with
  # the headline, access and trust, then the link. The name is shortened so
  # the post stays within TWEET_LIMIT as X counts it.
  def self.tweet_text(name:, extension_id:, extension_details:, rating:)
    details = extension_details.is_a?(Hash) ? extension_details : {}
    stars, count, size = %i[rating rating_count size].map { |key| tweet_field(ScanPage.value(details, key)) }
    rest = [
      "#{stars && count ? "#{stars} ★ (#{count})" : '? ★'}, #{size || '?KiB'}",
      "Overall: #{rating.overall} (#{rating.headline})",
      "Access: #{rating.access.name}. Trust: #{rating.trust.name}",
      "https://crxaminer.tech/scan/#{extension_id}"
    ]
    name = AiContextAnalysis.clean(name).squish.presence || "Unknown Extension"
    budget = TWEET_LIMIT - tweet_length(rest.join("\n")) - 1
    [shorten_for_tweet(name, budget), *rest].join("\n")
  rescue StandardError => e
    Rails.logger.error "Error formatting tweet text: #{e.message}"
    "Scan complete! https://crxaminer.tech/scan/#{extension_id}"
  end

  # A store field as short plain text, or nil.
  def self.tweet_field(value)
    return nil unless value.is_a?(String) || value.is_a?(Numeric)

    text = AiContextAnalysis.clean(value).squish
    return nil if text.empty?

    text.length > TWEET_FIELD_LIMIT ? "#{text[0, TWEET_FIELD_LIMIT - 1]}…" : text
  end

  # Length as X counts it: most Latin, Greek, Cyrillic and similar letters
  # and some punctuation count 1; everything else (CJK, emoji) counts 2. A
  # link counts 23, so counting it in full is safe.
  def self.tweet_length(text)
    text.each_char.sum do |char|
      code = char.ord
      code <= 4351 || code.between?(8192, 8205) || code.between?(8208, 8223) || code.between?(8242, 8247) ? 1 : 2
    end
  end

  def self.shorten_for_tweet(text, budget)
    return text if tweet_length(text) <= budget

    room = budget - tweet_length("…")
    kept = +""
    used = 0
    text.each_char do |char|
      used += tweet_length(char)
      break if used > room

      kept << char
    end
    "#{kept.rstrip}…"
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

  # Rule findings, then the access level, then the AI check (given the rule
  # findings and the access tier, never the overall line), then the rating
  # and the overall finding, which goes first.
  def analyze
    return [] unless @manifest

    ai_finding = analyze_with_ai
    @security_findings = rated_findings(ai_finding ? [ai_finding] : [])
    tweet_results
    @security_findings
  end

  # The overall finding (without listing data or AI) followed by every rule finding.
  def rule_findings
    [overall_finding(rating_for(nil, nil))] + findings_only.map(&:dup)
  end

  # The overall finding rated with this scan's listing details and the first
  # of ai_findings, then the rule findings, then ai_findings as given.
  def rated_findings(ai_findings)
    @rating = rating_for(@extension_details, ScanPage.value(ai_findings.first, :ai))
    [overall_finding(@rating)] + findings_only.map(&:dup) + ai_findings
  end

  # The highest finding level, or "Minimal" when nothing was found.
  def access_level
    highest_level(findings_only.map { |f| f[:severity] }) || "Minimal"
  end

  def manifest_summary
    @data = @manifest.is_a?(Hash) ? @manifest : {}
    ManifestSummary.new(
      manifest_version: manifest_version,
      permissions: required_permissions.keys,
      all_sites_host_access: required_sites.any? { |s| s.pattern.all_sites? },
      all_sites_content_scripts: content_script_sites.any? { |s| s.pattern.all_sites? }
    )
  end

  private

  # The rule findings, most severe first (no overall line, no AI finding).
  def findings_only
    @findings_only ||= begin
      @findings = []
      @data = @manifest.is_a?(Hash) ? @manifest : {}
      analyze_permissions
      analyze_site_access
      analyze_combinations
      analyze_optional
      analyze_csp
      analyze_manifest_version
      analyze_settings_overrides
      analyze_url_overrides
      analyze_main_world_scripts
      analyze_externally_connectable
      analyze_web_accessible_resources
      analyze_update_url
      analyze_oauth2
      most_severe_first(@findings).each(&:freeze).freeze
    end
  end

  def rating_for(extension_details, ai)
    ScanRating.new(access_level: access_level, extension_details: extension_details, ai: ai)
  end

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

      add_finding(entry.level, "Permission: #{name}",
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
      frames, early = script_detail_paths(scripts_everywhere.map { |s| s.path[1] }.uniq)
      clauses = []
      clauses << " They also run inside frames embedded in pages, such as ads and sign-in boxes." if frames.any?
      clauses << " They start before the page's own scripts, so they can change the page before it loads." if early.any?
      add_finding("High", "Scripts Run on All Websites",
                  "Its scripts run automatically in every website you open, where they can read and change the page, " \
                  "including what you type.#{clauses.join}#{suffix_note(scripts_everywhere)}",
                  rule: "content_script.all_sites", evidence: scripts_everywhere.map(&:path) + frames + early)
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
      add_finding("High", "Text Can Be Run as Code",
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

  # chrome_settings_overrides: the search engine, homepage and startup pages.
  def analyze_settings_overrides
    overrides = read(:chrome_settings_overrides)
    return unless overrides.is_a?(Hash)

    provider = lookup(overrides, :search_provider)
    if provider.is_a?(Hash)
      base = ["chrome_settings_overrides", "search_provider"]
      url = lookup(provider, :search_url)
      default = lookup(provider, :is_default) == true
      name = url_host(url) || plain_text(lookup(provider, :name)) || "a site it names"
      evidence = url.is_a?(String) ? [base + ["search_url"]] : [base]
      evidence << base + ["is_default"] if default
      lead = default ? "It makes #{name} your default search engine." : "It adds #{name} as a search engine in Chrome."
      add_finding("High", "Changes Your Search Engine",
                  "#{lead} Searches you type in the address bar then go to that site, which sees every search and " \
                  "chooses which results and ads you get.",
                  rule: "settings.search_provider", evidence: evidence)
    end

    pages = []
    evidence = []
    homepage = lookup(overrides, :homepage)
    if homepage.is_a?(String) && !homepage.strip.empty?
      pages << (url_host(homepage) || "a page it names")
      evidence << ["chrome_settings_overrides", "homepage"]
    end
    startup = lookup(overrides, :startup_pages)
    if startup.is_a?(Array)
      startup.each_with_index do |page, i|
        next unless page.is_a?(String) && !page.strip.empty?

        pages << (url_host(page) || "a page it names")
        evidence << ["chrome_settings_overrides", "startup_pages", i]
      end
    end
    return if evidence.empty?

    has_home = evidence.any? { |p| p.last == "homepage" }
    has_startup = evidence.any? { |p| p[1] == "startup_pages" }
    what = [("Homepage" if has_home), ("Startup Pages" if has_startup)].compact.join(" and ")
    add_finding("Medium", "Changes Your #{what}",
                "It sets the #{what.downcase} Chrome opens to #{pages.uniq.join(', ')}. That site then sees each visit " \
                "and can show you whatever it likes, including ads or misleading pages.",
                rule: "settings.homepage", evidence: evidence)
  end

  # chrome_url_overrides: Chrome pages it replaces with its own.
  def analyze_url_overrides
    overrides = read(:chrome_url_overrides)
    return unless overrides.is_a?(Hash)

    replaced = URL_OVERRIDE_PAGES.select { |key, _| lookup(overrides, key).is_a?(String) }
    return if replaced.empty?

    add_finding("Medium", "Replaces Chrome Pages",
                "It shows its own page instead of Chrome's #{replaced.values.to_sentence}. What you see there, " \
                "including any search box, links or ads, comes from the extension.",
                rule: "url_overrides", evidence: replaced.keys.map { |key| ["chrome_url_overrides", key] })
  end

  # Content scripts with world "MAIN" run in the page's own JavaScript
  # context instead of the isolated one extensions normally get.
  def analyze_main_world_scripts
    everywhere = []
    named = []
    hosts = []
    content_scripts.each do |script, i|
      world = lookup(script, :world)
      next unless world.is_a?(String) && world.casecmp?("MAIN")

      sites = content_script_sites.select { |s| s.path[1] == i }
      if sites.any? { |s| s.pattern.all_sites? }
        everywhere << ["content_scripts", i, "world"]
      elsif sites.any?
        named << ["content_scripts", i, "world"]
        hosts.concat(sites.filter_map { |s| s.pattern.domain || (s.pattern.file? ? "local files" : nil) })
      end
    end

    explain = "the page's own JavaScript, not the separate space Chrome normally gives extensions. There they can " \
              "change how the page's own code behaves, for example read or alter what the page sends and receives, " \
              "and the page's code can reach them too."
    if everywhere.any?
      add_finding("Critical", "Scripts Run Inside Every Website's Own Code",
                  "On every website, some of its scripts run inside #{explain}",
                  rule: "content_script.main_world_all_sites", evidence: everywhere)
    end
    return if named.empty?

    where = hosts.uniq.any? ? "On #{short_list(hosts.uniq)}" : "On the sites it names"
    add_finding("Medium", "Scripts Run Inside Sites' Own Code",
                "#{where}, some of its scripts run inside #{explain}",
                rule: "content_script.main_world", evidence: named)
  end

  # externally_connectable.matches: websites allowed to message the
  # extension. "ids" alone (other extensions) raises nothing.
  def analyze_externally_connectable
    connectable = read(:externally_connectable)
    return unless connectable.is_a?(Hash)

    matches = lookup(connectable, :matches)
    return unless matches.is_a?(Array)

    sites = matches.each_with_index.filter_map do |pattern, i|
      parsed = MatchPattern.parse(pattern)
      [parsed, ["externally_connectable", "matches", i]] if parsed.valid?
    end
    return if sites.empty?

    wide = sites.any? do |parsed, _|
      parsed.all_urls? || parsed.host == "*" || parsed.subdomains? || parsed.scheme != "https"
    end
    names = sites.map { |parsed, _| parsed.all_sites? ? "every website" : (parsed.domain || parsed.to_s) }.uniq
    exposure = "If the extension handles those messages carelessly, a flaw could be used by those sites, or by anyone " \
               "who manages to put a page on them."
    if wide
      add_finding("Medium", "Many Web Pages Can Message It",
                  "Pages on #{short_list(names)} can send messages to the extension. Some entries cover every subdomain " \
                  "or allow plain http, so many pages qualify, and a page on an unencrypted connection can be changed " \
                  "by others on the network. #{exposure}",
                  rule: "externally_connectable.wide", evidence: sites.map(&:last))
    else
      add_finding("Low", "Named Websites Can Message It",
                  "Pages on #{short_list(names)} can send messages to the extension. #{exposure}",
                  rule: "externally_connectable", evidence: sites.map(&:last))
    end
  end

  # Files any website can load. A Manifest V2 entry is a plain string and
  # open to every site; a Manifest V3 entry lists the sites in "matches".
  # extension_ids (other extensions) is not about websites and is ignored.
  # Medium when a resource glob exposes every file of the extension.
  def analyze_web_accessible_resources
    entries = read(:web_accessible_resources)
    return unless entries.is_a?(Array)

    evidence = []
    resources = []
    everything = []
    entries.each_with_index do |entry, i|
      if entry.is_a?(String)
        evidence << ["web_accessible_resources", i]
        resources << entry
        everything << ["web_accessible_resources", i] if whole_extension_glob?(entry)
      elsif entry.is_a?(Hash)
        matches = lookup(entry, :matches)
        list = lookup(entry, :resources)
        next unless matches.is_a?(Array) && list.is_a?(Array)

        open = matches.each_index.select { |j| MatchPattern.parse(matches[j]).all_sites? }
        files = list.each_index.select { |j| list[j].is_a?(String) }
        next if open.empty? || files.empty?

        evidence.concat(open.map { |j| ["web_accessible_resources", i, "matches", j] })
        resources.concat(files.map { |j| list[j] })
        everything.concat(files.select { |j| whole_extension_glob?(list[j]) }.map { |j| ["web_accessible_resources", i, "resources", j] })
      end
    end
    return if evidence.empty?

    shown = short_list(resources.filter_map { |r| plain_text(r) }.uniq)
    risk = "That lets any site detect that you have the extension, and pages or scripts among them could be " \
           "opened or misused by a site."
    if everything.any?
      add_finding("Medium", "Every File Open to All Websites",
                  "Any website can load every file in the extension (#{shown}). #{risk}",
                  rule: "web_accessible_resources.everything", evidence: evidence + everything)
    else
      add_finding("Low", "Files Open to All Websites",
                  "Any website can load these files from the extension: #{shown}. #{risk}",
                  rule: "web_accessible_resources.all_sites", evidence: evidence)
    end
  end

  # Packages downloaded from the Chrome Web Store always carry Google's
  # update URL, so this is not expected to fire for scans made here; it
  # matters for manifests that came from somewhere else.
  def analyze_update_url
    url = read(:update_url)
    return unless url.is_a?(String) && !url.strip.empty?

    # A value with no readable host is not an update server Chrome could use.
    host = url_host(url)
    return if host.nil? || host == STORE_UPDATE_HOST

    add_finding("Critical", "Updates From Outside the Chrome Web Store",
                "Its updates would come from #{host} instead of the Chrome Web Store, so new " \
                "versions would skip the store's review and could change what it does at any time.",
                rule: "update_url.external", evidence: [["update_url"]])
  end

  # oauth2.scopes: Google account access it asks for through the identity API.
  def analyze_oauth2
    oauth = read(:oauth2)
    return unless oauth.is_a?(Hash)

    scopes = lookup(oauth, :scopes)
    return unless scopes.is_a?(Array)

    data = []
    sign_in = []
    scopes.each_with_index do |scope, i|
      next unless scope.is_a?(String) && !scope.strip.empty?

      kind = oauth_kind(scope)
      (kind ? data : sign_in) << [kind, ["oauth2", "scopes", i]]
    end

    if data.any?
      add_finding("Medium", "Asks for Google Account Data",
                  "It asks for access to data in your Google account: #{short_list(data.map(&:first).uniq)}. " \
                  "Once you agree, it can use that data through Google's services, outside the browser too.",
                  rule: "oauth2.account_data", evidence: data.map(&:last))
    elsif sign_in.any?
      add_finding("Low", "Google Sign-In",
                  "Once you agree, it can sign you in with your Google account and read your name and email address.",
                  rule: "oauth2.sign_in", evidence: sign_in.map(&:last))
    end
  end

  # --- helpers --------------------------------------------------------------

  # [script, index] for each content script that is an object.
  def content_scripts
    scripts = read(:content_scripts)
    return [] unless scripts.is_a?(Array)

    scripts.each_with_index.select { |script, _| script.is_a?(Hash) }
  end

  # For the content scripts at these indexes: paths of the keys that make
  # them run in embedded frames, and of run_at "document_start".
  def script_detail_paths(indexes)
    scripts = read(:content_scripts)
    frames = []
    early = []
    indexes.each do |i|
      script = scripts.is_a?(Array) ? scripts[i] : nil
      next unless script.is_a?(Hash)

      %i[all_frames match_about_blank match_origin_as_fallback].each do |key|
        frames << ["content_scripts", i, key.to_s] if lookup(script, key) == true
      end
      early << ["content_scripts", i, "run_at"] if lookup(script, :run_at) == "document_start"
    end
    [frames, early]
  end

  # nil for a sign-in scope, otherwise the kind of account data it reaches.
  def oauth_kind(scope)
    name = scope.strip.downcase.sub(%r{\Ahttps?://www\.googleapis\.com/auth/}, "").sub(%r{\Ahttps?://}, "").delete_suffix("/")
    return nil if OAUTH_SIGN_IN_SCOPES.include?(name) || OAUTH_SIGN_IN_SCOPES.include?(name.split(".").first)

    OAUTH_DATA_SCOPES[name] || OAUTH_DATA_SCOPES[name.split(".").first] ||
      "other account data (#{plain_text(scope) || 'a scope it names'})"
  end

  def whole_extension_glob?(resource)
    %w[* ** /* /** *.* /*.*].include?(resource.strip)
  end

  # The host of an http(s) URL, lowercased; nil for anything else.
  def url_host(url)
    return nil unless url.is_a?(String)

    url.strip[%r{\Ahttps?://(?:[^/?#@\s]*@)?([^/?#:\s]+)}i, 1]&.downcase
  end

  # Untrusted text as a short single line, or nil.
  def plain_text(value)
    return nil unless value.is_a?(String)

    text = value.scrub("?").squish
    return nil if text.empty?

    text.length > 60 ? "#{text[0, 59]}…" : text
  end

  # "a, b, c, d, e and 3 more"
  def short_list(names, limit = 5)
    return names.join(", ") if names.size <= limit

    "#{names.first(limit).join(', ')} and #{names.size - limit} more"
  end

  # Most severe first, keeping the rule order within a level. The AI step
  # only receives the first findings of a long list, so the Critical and High
  # ones must not sit behind a long run of routine permissions.
  def most_severe_first(findings)
    findings.sort_by.with_index { |finding, index| [LEVELS.index(finding[:severity]) || LEVELS.size, index] }
  end

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

  # The combined verdict, stored first in the list:
  #   severity:      the overall level (ScanRating#overall)
  #   title:         "Overall Risk: <overall>" (statistics and older code find it by that title)
  #   description:   both ratings and the advice, in plain words
  #   rules_version: RULES_VERSION, so stored scans can be re-rated when the rules change
  #   access:        the access level, the highest finding level ("Minimal" when none)
  #   trust:         the trust level key (ScanRating::TRUST_LEVELS)
  #   headline:      the two combined in a few words
  def overall_finding(rating)
    {
      severity: rating.overall,
      title: "#{OVERALL_TITLE_PREFIX}#{rating.overall}",
      description: overall_description(rating),
      rules_version: RULES_VERSION,
      **rating.to_stored
    }
  end

  def overall_description(rating)
    found = findings_only.size
    basis = found.zero? ? "no rule found anything to flag" : "the highest of #{found} rule #{found == 1 ? 'finding' : 'findings'}"
    "Access: #{rating.access.name} (#{basis}). Trust: #{rating.trust.name}. #{rating.advice}"
  end

  # The AI finding, or nil when the check fails, is refused or is not
  # configured; the scan is then rated from the listing alone.
  def analyze_with_ai
    AiContextAnalysis.new(
      manifest: @manifest,
      extension_details: @extension_details,
      extension_name: @extension_name,
      findings: findings_only,
      access: ScanRating.access_tier(access_level).name,
      previous_findings: @previous_findings,
      client: @ai_client
    ).call
  rescue StandardError => e
    # AiContextAnalysis does not raise; this keeps the rule findings even if it ever does.
    Rails.logger.error "AI analysis failed for #{@extension_id}: #{e.class}: #{e.message}"
    nil
  end

  def tweet_results
    tweet_text = self.class.tweet_text(name: @extension_name, extension_id: @extension_id,
                                       extension_details: @extension_details, rating: @rating)
    Rails.logger.info tweet_text
    TwitterClient.new.post_tweet(tweet_text)
  rescue StandardError => e
    Rails.logger.error "Failed to tweet scan results: #{e.message}"
  end
end
