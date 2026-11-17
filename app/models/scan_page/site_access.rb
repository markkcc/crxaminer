module ScanPage
  # Which websites an extension can reach, in plain words, from its host
  # permissions, content script matches and (Manifest V2) the match patterns
  # listed inside "permissions".
  class SiteAccess
    Pattern = Struct.new(:pattern, :source, keyword_init: true)

    SOURCES = {
      host_permissions: "Host permissions",
      content_scripts: "Content script matches",
      permissions: "Listed in permissions (Manifest V2)",
      optional_host_permissions: "Optional host permissions",
      optional_permissions: "Listed in optional permissions (Manifest V2)"
    }.freeze

    # Schemes whose "*" host means every website.
    WEB_SCHEMES = %w[* http https ws wss ftp].freeze
    PATTERN_SHAPE = %r{\A([a-z*][a-z0-9+.*-]*)://([^/]*)}i

    def initialize(manifest)
      @manifest = manifest.is_a?(Hash) ? manifest : {}
    end

    # Match patterns can also appear in "permissions" in Manifest V2.
    def self.pattern?(entry)
      entry.is_a?(String) && (entry == "<all_urls>" || entry.include?("://") || entry == "*")
    end

    def manifest_v2?
      ScanPage.value(@manifest, :manifest_version).to_i < 3
    end

    def patterns
      @patterns ||= begin
        found = ScanPage.strings(ScanPage.value(@manifest, :host_permissions))
          .map { |p| Pattern.new(pattern: p, source: :host_permissions) }
        found += content_script_matches.map { |p| Pattern.new(pattern: p, source: :content_scripts) }
        if manifest_v2?
          found += ScanPage.list(ScanPage.value(@manifest, :permissions)).select { |p| self.class.pattern?(p) }
            .map { |p| Pattern.new(pattern: p, source: :permissions) }
        end
        found.uniq
      end
    end

    # Sites it can ask for later; Chrome prompts the user at that point.
    def optional_patterns
      @optional_patterns ||= begin
        raw = ScanPage.value(@manifest, :raw)
        found = ScanPage.strings(ScanPage.value(raw, :optional_host_permissions))
          .map { |p| Pattern.new(pattern: p, source: :optional_host_permissions) }
        if manifest_v2?
          found += ScanPage.list(ScanPage.value(@manifest, :optional_permissions)).select { |p| self.class.pattern?(p) }
            .map { |p| Pattern.new(pattern: p, source: :optional_permissions) }
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
      patterns.any? { |p| all_sites_pattern?(p.pattern) }
    end

    def file_access?
      patterns.any? { |p| p.pattern.match?(%r{\Afile://}i) }
    end

    # Named sites, without duplicates, as they appear in the patterns.
    def sites
      @sites ||= patterns.filter_map { |p| site_name(p.pattern) }.uniq.sort
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
      notes << "It can also read local files (file:// URLs) if you allow file access in its settings." if file_access?
      notes << "It can also use the current tab after you click the extension (activeTab)." if active_tab? && %i[all named].include?(kind)
      notes
    end

    private

    def content_script_matches
      ScanPage.list(ScanPage.value(@manifest, :content_scripts)).flat_map do |script|
        ScanPage.strings(ScanPage.value(script, :matches))
      end
    end

    def all_sites_pattern?(pattern)
      return true if pattern == "<all_urls>" || pattern == "*"

      scheme, host = parse(pattern)
      host == "*" && WEB_SCHEMES.include?(scheme)
    end

    # "https://*.example.com/*" -> "*.example.com"; other schemes keep theirs.
    def site_name(pattern)
      return nil if all_sites_pattern?(pattern)

      scheme, host = parse(pattern)
      return nil if scheme.nil? || scheme == "file" || host.to_s.empty?

      %w[* http https].include?(scheme) ? host.downcase : "#{scheme}://#{host.downcase}"
    end

    def parse(pattern)
      match = PATTERN_SHAPE.match(pattern)
      match ? [match[1].downcase, match[2]] : [nil, nil]
    end
  end
end
