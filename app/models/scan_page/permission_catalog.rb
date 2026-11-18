module ScanPage
  # Plain-language descriptions, ratings and documentation links for
  # Chrome's documented extension permissions, and the rows of the
  # Permissions table. Everything comes from ExtensionAnalyzerData::PERMISSIONS,
  # the table the rule engine rates from, so the column always agrees with
  # the findings.
  class PermissionCatalog
    Row = Struct.new(:name, :description, :rating, :doc_url, keyword_init: true)

    DOCS_BASE = "https://developer.chrome.com/docs/extensions/reference/api/".freeze
    PERMISSIONS_LIST_URL = "https://developer.chrome.com/docs/extensions/reference/permissions-list".freeze

    def self.description(name)
      ExtensionAnalyzerData.permission(name)&.allows
    end

    def self.doc_url(name)
      entry = ExtensionAnalyzerData.permission(name)
      return nil unless entry

      entry.doc_page ? DOCS_BASE + entry.doc_page : PERMISSIONS_LIST_URL
    end

    # The level the rule engine gives the name ("Critical" to "Low"), or nil
    # for a name it does not know. Optional permissions are rated one level
    # lower, because Chrome asks the user before granting them.
    def self.rating(name, optional: false)
      level = ExtensionAnalyzerData.permission_level(name)
      level && optional ? ExtensionAnalyzerData.optional_level(level) : level
    end

    def self.row(entry, optional: false)
      name = ScanPage.text(entry)
      known = entry.is_a?(String)
      Row.new(name: name, description: known ? description(entry) : nil,
              rating: known ? rating(entry, optional: optional) : nil, doc_url: known ? doc_url(entry) : nil)
    end

    def initialize(manifest)
      @manifest = manifest.is_a?(Hash) ? manifest : {}
    end

    # API permissions only. In Manifest V2 match patterns can sit in the same
    # list; SiteAccess shows those. Manifest V3 ignores patterns there, so they
    # stay in the table as unknown entries rather than disappear.
    def required
      @required ||= rows(:permissions, optional: false)
    end

    def optional
      @optional ||= rows(:optional_permissions, optional: true)
    end

    private

    def manifest_v2?
      ScanPage.value(@manifest, :manifest_version).to_i < 3
    end

    def rows(key, optional:)
      ScanPage.list(ScanPage.value(@manifest, key))
        .reject { |entry| entry.nil? || (manifest_v2? && SiteAccess.pattern?(entry)) }
        .uniq
        .map { |entry| self.class.row(entry, optional: optional) }
    end
  end
end
