module ScanPage
  # Everything the scan results page shows, built once per request from the
  # stored manifest and findings. Each part is computed on first use.
  class Report
    # Grouping by domain takes a few milliseconds for ordinary scans (about
    # 3 ms for 1,100 URLs, 30 ms for 4,300) but a few hundred for the rare
    # ones with tens of thousands of URLs. Only those are cached per stored
    # scan: caching smaller ones saves little and fills the file cache.
    NETWORK_CACHE_OVER = 5_000

    # cache_key identifies the stored scan (for example its id and update
    # time); without it nothing is cached.
    def initialize(manifest:, security_findings:, extension_details: nil, cache_key: nil)
      @manifest = manifest.is_a?(Hash) ? manifest : {}
      @security_findings = security_findings
      @extension_details = extension_details
      @cache_key = cache_key
    end

    # The access and trust ratings and the headline that combines them.
    def rating
      @rating ||= ScanRating.for_scan(security_findings: @security_findings, extension_details: @extension_details)
    end

    # The level shown for this scan in lists and statistics (ScanDisplayLevel).
    def display_level
      @display_level ||= ScanDisplayLevel.for(@security_findings)
    end

    # The stored AI finding (a hash, symbol or string keys), or nil.
    def ai_finding
      @ai_finding ||= ScanPage.list(@security_findings).find { |f| f.is_a?(Hash) && FindingGroups.ai?(f) }
    end

    AiCheck = Struct.new(:concern_level, :purpose_fit, :summary, :trust_factors, :concerns, :recommendations,
                         :model, :analyzed_at, keyword_init: true)

    # The AI check in the current format, or nil when there is none or it
    # was stored in the old format (with a risk level). Lists hold strings only.
    def ai_check
      return @ai_check if defined?(@ai_check)

      ai = ScanPage.value(ai_finding, :ai)
      concern = ScanPage.value(ai, :concern_level)
      fit = ScanPage.value(ai, :purpose_fit)
      @ai_check = if ScanRating::CONCERN_LEVELS.include?(concern) && ScanRating::PURPOSE_FITS.include?(fit)
        texts = %i[summary model analyzed_at].to_h { |key| [key, ScanPage.value(ai, key).then { |v| v.is_a?(String) ? v : nil }] }
        lists = %i[trust_factors concerns recommendations].to_h { |key| [key, ScanPage.strings(ScanPage.value(ai, key))] }
        AiCheck.new(concern_level: concern, purpose_fit: fit, **texts, **lists)
      end
    end

    def finding_groups
      @finding_groups ||= FindingGroups.new(@security_findings)
    end

    def site_access
      @site_access ||= SiteAccess.new(@manifest)
    end

    def permissions
      @permissions ||= PermissionCatalog.new(@manifest)
    end

    def network
      @network ||= begin
        domains = NetworkDomains.new(ScanPage.value(@manifest, :embedded_urls))
        if @cache_key && domains.url_count > NETWORK_CACHE_OVER
          Rails.cache.fetch(["scan-page-network", NetworkDomains::VERSION, *@cache_key]) { domains.summary }
        else
          domains.summary
        end
      end
    end

    def manifest_document
      @manifest_document ||= ManifestDocument.new(ScanPage.value(@manifest, :raw))
    end

    def content_security_policy
      ScanPage.list(ScanPage.value(@manifest, :content_security_policy)).map { |p| ScanPage.text(p) }
    end

    # Required API permissions plus the site patterns it asks for up front.
    def permission_count
      permissions.required.size + site_access.patterns.map(&:pattern).uniq.size
    end

    # Where each rule finding sits in the manifest, and the notes shown there.
    def manifest_notes
      @manifest_notes ||= ManifestNotes.new(manifest_document, finding_groups.findings)
    end

    # Manifest line numbers for one rule finding (a FindingGroups::Finding
    # from finding_groups), ascending.
    def finding_lines(finding)
      manifest_notes.lines_for(finding)
    end

    # Line number => the notes (ManifestNotes::Note) on that line, most
    # severe first.
    def flagged_lines
      manifest_notes.by_line
    end
  end
end
