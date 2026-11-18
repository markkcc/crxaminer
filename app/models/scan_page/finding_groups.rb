module ScanPage
  # Sorts the rule engine's findings into areas for the Overview tab, and
  # separates routine permissions so they can be collapsed into one line.
  # Severities and texts are passed through unchanged.
  class FindingGroups
    # rule and evidence are only present on findings written by the current
    # rule engine (see ExtensionSecurityAnalyzer#add_finding): rule is its
    # stable id, evidence the manifest paths the finding points at. Findings
    # stored by older versions have neither (nil and []).
    Finding = Struct.new(:severity, :title, :description, :permission, :rule, :evidence, keyword_init: true)

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
        "#{routine.size} routine #{noun}: #{routine.map(&:permission).join(' · ')}"
      end
    end

    AREAS = {
      site_access: "Site access",
      browser: "Browser capabilities",
      code_policy: "Code and policy",
      network: "Network destinations",
      other: "Other"
    }.freeze

    # Permissions whose findings are collapsed by default. They keep their
    # stored severity when expanded; this only changes how much space they take.
    ROUTINE_PERMISSIONS = %w[storage unlimitedStorage notifications contextMenus activeTab].freeze

    # Titles written by ExtensionSecurityAnalyzer. Anything else (including
    # titles from older versions of the engine) lands in "Other".
    PERMISSION_TITLE = /\A\w+-Risk Permission: (.+)\z/m
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
      Finding.new(
        severity: ScanPage.value(hash, :severity).to_s,
        title: title,
        description: ScanPage.value(hash, :description).then { |d| d.nil? ? "" : ScanPage.text(d) },
        permission: title[PERMISSION_TITLE, 1],
        rule: ScanPage.value(hash, :rule).then { |r| r.is_a?(String) ? r : nil },
        evidence: ScanPage.paths(ScanPage.value(hash, :evidence))
      )
    end

    def routine?(finding)
      ROUTINE_PERMISSIONS.include?(finding.permission)
    end

    # "<all_urls>" and match patterns are about which sites, not which APIs.
    def host_pattern?(name)
      name == "<all_urls>" || name.include?("://")
    end
  end
end
