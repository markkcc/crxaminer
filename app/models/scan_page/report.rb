module ScanPage
  # Everything the scan results page shows, built once per request from the
  # stored manifest and findings. Each part is computed on first use.
  class Report
    # Grouping tens of thousands of URLs by domain takes a few hundred
    # milliseconds, so summaries for long lists are cached per stored scan.
    NETWORK_CACHE_OVER = 1_000

    # cache_key identifies the stored scan (for example its id and update
    # time); without it nothing is cached.
    def initialize(manifest:, security_findings:, cache_key: nil)
      @manifest = manifest.is_a?(Hash) ? manifest : {}
      @security_findings = security_findings
      @cache_key = cache_key
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

    # Manifest line numbers for each rule finding, keyed by title.
    def finding_lines
      @finding_lines ||= finding_groups.findings.to_h { |f| [f.title, manifest_document.lines_for(f.title)] }
    end

    # Line number => titles of the findings that point at it.
    def flagged_lines
      @flagged_lines ||= finding_lines.each_with_object(Hash.new { |h, k| h[k] = [] }) do |(title, numbers), map|
        numbers.each { |n| map[n] << title }
      end
    end
  end
end
