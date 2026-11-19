module ScanPage
  # Sorts the rule engine's findings into areas for the Overview tab, and
  # separates routine permissions so they can be collapsed into one line.
  # Severities and texts are passed through unchanged.
  #
  # Findings written by the current engine carry a rule id (see
  # ExtensionAnalyzerData::RULES) and are grouped by it. Findings stored by
  # older versions (about 20,000 scans) have only a title and are grouped by
  # the legacy title mapping below.
  class FindingGroups
    # rule and evidence are only present on findings written by the current
    # rule engine (see ExtensionSecurityAnalyzer#add_finding): rule is its
    # stable id, evidence the manifest paths the finding points at. Findings
    # stored by older versions have neither (nil and []). optional is true
    # for items the extension can only ask for later.
    Finding = Struct.new(:severity, :title, :description, :permission, :rule, :evidence, :optional, keyword_init: true)

    Area = Struct.new(:key, :name, :findings, :routine, keyword_init: true) do
      def empty?
        findings.empty? && routine.empty?
      end

      def count
        findings.size + routine.size
      end

      # "5 routine permissions: storage · notifications · ..."
      def routine_label
        noun = routine.size == 1 ? "permission" : "permissions"
        names = routine.map { |f| f.optional ? "#{f.permission} (optional)" : f.permission }
        "#{routine.size} routine #{noun}: #{names.join(' · ')}"
      end
    end

    AREAS = {
      site_access: "Site access",
      browser: "Browser capabilities",
      code_policy: "Code and policy",
      network: "Network destinations",
      other: "Other"
    }.freeze

    # Areas by rule id, matched on the id with any "optional." prefix removed.
    RULE_AREAS = {
      "permission" => :browser,
      "combination" => :browser,
      "host" => :site_access,
      "content_script" => :site_access,
      "csp" => :code_policy,
      "manifest" => :code_policy,
      # What the extension changes in Chrome, and account access.
      "settings" => :browser,
      "url_overrides" => :browser,
      "oauth2" => :browser,
      # Which websites can reach the extension.
      "externally_connectable" => :site_access,
      "web_accessible_resources" => :site_access,
      "update_url" => :code_policy
    }.freeze

    OPTIONAL_PREFIX = "optional.".freeze

    # Titles the current engine gives permission findings.
    PERMISSION_TITLE = /\A\w+-Risk Permission: (.+)\z/m
    OPTIONAL_PERMISSION_TITLE = /\AOptional Permission: (.+)\z/m

    # Legacy: how findings stored before rule ids existed are recognised.
    # COMBINATION_PREFIX and the titles below are only written by older
    # versions of the engine; anything unknown lands in "Other".
    COMBINATION_PREFIX = "Dangerous Permission Combination:".freeze
    TITLE_AREAS = {
      "Broad Host Permissions" => :site_access,
      "Access to Sensitive Domains" => :site_access,
      "Broad Content Script Injection" => :site_access,
      "Older Manifest Version" => :code_policy,
      "Unsafe WebAssembly Execution" => :code_policy,
      "Unsafe JavaScript Evaluation" => :code_policy
    }.freeze

    def self.overall?(finding)
      ScanPage.value(finding, :title).to_s.downcase.include?("overall risk")
    end

    def self.ai?(finding)
      ScanPage.value(finding, :severity) == "Info" && ScanPage.value(finding, :title) == "AI Context Analysis"
    end

    # The rules version stored on the overall finding; 1 for scans rated
    # before versions were recorded.
    def self.rules_version(findings)
      overall = ScanPage.list(findings).find { |f| f.is_a?(Hash) && overall?(f) }
      version = ScanPage.value(overall, :rules_version)
      version.is_a?(Integer) ? version : 1
    end

    def initialize(security_findings)
      @raw = ScanPage.list(security_findings).select { |f| f.is_a?(Hash) }
    end

    # The rule findings: everything except the overall rating and the AI verdict.
    def findings
      @findings ||= @raw
        .reject { |f| self.class.overall?(f) || self.class.ai?(f) }
        .map { |f| build(f) }
        .sort_by { |f| [ExtensionAnalyzerData::SEVERITY_ORDER.fetch(f.severity.to_s.downcase, 999), f.title.to_s] }
    end

    # Every area in a fixed order, so empty ones can say so. "Other" is only
    # listed when something landed in it.
    def areas
      @areas ||= begin
        grouped = findings.group_by { |f| area_for(f) }
        AREAS.filter_map do |key, name|
          items = grouped.fetch(key, [])
          next if key == :other && items.empty?

          routine, notable = items.partition { |f| routine?(f) }
          Area.new(key: key, name: name, findings: notable, routine: routine)
        end
      end
    end

    def area_for(finding)
      if finding.rule
        area = RULE_AREAS[finding.rule.delete_prefix(OPTIONAL_PREFIX).split(".").first]
        return area if area
      end

      title = finding.title.to_s
      if finding.permission
        host_pattern?(finding.permission) ? :site_access : :browser
      elsif title.start_with?(COMBINATION_PREFIX)
        :browser
      else
        TITLE_AREAS.fetch(title, :other)
      end
    end

    private

    def build(hash)
      title = ScanPage.value(hash, :title)
      title = title.nil? ? "" : ScanPage.text(title)
      rule = ScanPage.value(hash, :rule).then { |r| r.is_a?(String) ? r : nil }
      optional_name = title[OPTIONAL_PERMISSION_TITLE, 1] if rule
      Finding.new(
        severity: ScanPage.value(hash, :severity).to_s,
        title: title,
        description: ScanPage.value(hash, :description).then { |d| d.nil? ? "" : ScanPage.text(d) },
        permission: title[PERMISSION_TITLE, 1] || optional_name,
        rule: rule,
        evidence: ScanPage.paths(ScanPage.value(hash, :evidence)),
        optional: rule.to_s.start_with?(OPTIONAL_PREFIX)
      )
    end

    # Permissions the shared table rates Low are folded into one line,
    # whatever severity the finding was stored with (old scans stored them
    # as Medium). Optional ones fold only when the permission itself is Low.
    def routine?(finding)
      ExtensionAnalyzerData.permission_level(finding.permission) == "Low"
    end

    # "<all_urls>" and match patterns are about which sites, not which APIs.
    def host_pattern?(name)
      name == "<all_urls>" || name.include?("://")
    end
  end
end
