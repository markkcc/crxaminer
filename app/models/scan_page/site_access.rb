module ScanPage
  # Which websites an extension can reach, in plain words, from its host
  # permissions, content script matches and (Manifest V2) the match patterns
  # listed inside "permissions". Patterns are read by MatchPattern, the same
  # parser the rule engine uses, so the page and the findings agree.
  class SiteAccess
    # rating: the level the rule engine gives this entry on its own (all
    # sites, local files, a sensitive site), or nil when it is not flagged.
    Pattern = Struct.new(:pattern, :source, :rating, keyword_init: true)

    SOURCES = {
      host_permissions: "Host permissions",
      content_scripts: "Content script matches",
      permissions: "Listed in permissions (Manifest V2)",
      optional_host_permissions: "Optional host permissions",
      optional_permissions: "Listed in optional permissions (Manifest V2)"
    }.freeze

    OPTIONAL_SOURCES = %i[optional_host_permissions optional_permissions].freeze

    def initialize(manifest)
      @manifest = manifest.is_a?(Hash) ? manifest : {}
    end

    # Entries of "permissions" that are site patterns rather than API names
    # ("<all_urls>", "https://example.com/*"). In Manifest V2 they grant site
    # access; Manifest V3 ignores them there.
    def self.pattern?(entry)
      entry.is_a?(String) && (entry == MatchPattern::ALL_URLS || entry.include?("://"))
    end

    # The rule engine's level for one pattern on its own, or nil.
    def self.rating(pattern, optional: false)
      parsed = pattern.is_a?(MatchPattern) ? pattern : MatchPattern.parse(pattern)
      level = if parsed.all_sites? then "High"
              elsif parsed.file? then "Low"
              elsif sensitive?(parsed) then "Medium"
              end
      level && optional ? ExtensionAnalyzerData.optional_level(level) : level
    end

    def self.sensitive?(parsed)
      domain = parsed.registrable_domain
      !domain.nil? && !ExtensionAnalyzerData.sensitive_category(domain, parsed.domain_label).nil?
    end

    def manifest_v2?
      ScanPage.value(@manifest, :manifest_version).to_i < 3
    end

    def patterns
      @patterns ||= begin
        found = ScanPage.strings(ScanPage.value(@manifest, :host_permissions)).map { |p| build(p, :host_permissions) }
        found += content_script_matches.map { |p| build(p, :content_scripts) }
        if manifest_v2?
          found += ScanPage.list(ScanPage.value(@manifest, :permissions)).select { |p| self.class.pattern?(p) }
            .map { |p| build(p, :permissions) }
        end
        found.uniq
      end
    end

    # Sites it can ask for later; Chrome prompts the user at that point.
    # Scans stored before optional_host_permissions was extracted have it in raw only.
    def optional_patterns
      @optional_patterns ||= begin
        hosts = ScanPage.value(@manifest, :optional_host_permissions)
        hosts = ScanPage.value(ScanPage.value(@manifest, :raw), :optional_host_permissions) unless hosts.is_a?(Array)
        found = ScanPage.strings(hosts).map { |p| build(p, :optional_host_permissions) }
        if manifest_v2?
          found += ScanPage.list(ScanPage.value(@manifest, :optional_permissions)).select { |p| self.class.pattern?(p) }
            .map { |p| build(p, :optional_permissions) }
        end
        found.uniq
      end
    end

    def patterns_by_source
      patterns.group_by(&:source)
    end

    def active_tab?
      ScanPage.list(ScanPage.value(@manifest, :permissions)).include?("activeTab")
    end

    def all_sites?
      parsed.any?(&:all_sites?)
    end

    def file_access?
      parsed.any?(&:file?)
    end

    # Named sites, without duplicates, as they appear in the patterns.
    def sites
      @sites ||= parsed.filter_map { |p| site_name(p) }.uniq.sort
    end

    # :all, :named, :active_tab or :none
    def kind
      if all_sites? then :all
      elsif sites.any? then :named
      elsif active_tab? then :active_tab
      else :none
      end
    end

    def summary
      case kind
      when :all then "All websites"
      when :named then sites.size == 1 ? "1 named site" : "#{sites.size} named sites"
      when :active_tab then "Only when you click the extension"
      else "No website access"
      end
    end

    # Extra facts that the headline does not cover.
    def notes
      notes = []
      parsed.select(&:public_suffix_wildcard?).uniq(&:to_s).each do |p|
        notes << "#{p} covers every site ending in .#{p.domain}, so it counts as all websites."
      end
      notes << "It can also read local files (file:// URLs) if you allow file access in its settings." if file_access?
      notes << "It can also use the current tab after you click the extension (activeTab)." if active_tab? && %i[all named].include?(kind)
      notes
    end

    private

    def build(pattern, source)
      Pattern.new(pattern: pattern, source: source, rating: self.class.rating(pattern, optional: OPTIONAL_SOURCES.include?(source)))
    end

    # Valid patterns only: Chrome ignores the rest, and so does the summary.
    def parsed
      @parsed ||= patterns.map { |p| MatchPattern.parse(p.pattern) }.select(&:valid?)
    end

    def content_script_matches
      ScanPage.list(ScanPage.value(@manifest, :content_scripts)).flat_map do |script|
        ScanPage.strings(ScanPage.value(script, :matches))
      end
    end

    # "https://*.example.com/*" -> "*.example.com"; schemes other than web
    # ones keep theirs ("chrome://favicon"). nil for all-site and file
    # patterns and for a wildcard-only host.
    def site_name(parsed)
      return nil if parsed.all_sites? || parsed.file? || parsed.host.to_s.empty? || parsed.host == "*"

      MatchPattern::WEB_SCHEMES.include?(parsed.scheme) ? parsed.host : "#{parsed.scheme}://#{parsed.host}"
    end
  end
end
