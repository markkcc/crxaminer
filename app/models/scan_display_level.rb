# The one level shown for a stored scan in the statistics, the recent-scans
# list and posts to X. Ruby (ScanDisplayLevel.for) and SQL
# (ScanDisplayLevel.where_level) follow the same rule:
#
#   rules version 4 or later (the overall finding carries the combined
#   verdict): the overall finding's severity.
#   older scans: the level at the start of the old AI finding's description
#   ("Risk Level: High"), else the overall finding's severity.
#
# Stored findings can be anything (old formats, string or symbol keys,
# junk); nothing here raises.
module ScanDisplayLevel
  LEVELS = ExtensionAnalyzerData::OVERALL_LEVELS
  VERDICT_VERSION = 4
  LEGACY_AI_PREFIX = "Risk Level:".freeze

  module_function

  # A level from LEVELS, or nil when the scan has none.
  def for(security_findings)
    findings = ScanPage.list(security_findings).select { |f| f.is_a?(Hash) }
    overall = findings.find { |f| ScanPage::FindingGroups.overall?(f) }
    overall_level = level(ScanPage.value(overall, :severity))
    return overall_level if ScanPage::FindingGroups.rules_version(findings) >= VERDICT_VERSION

    legacy = findings.find { |f| legacy_ai?(f) }
    legacy ? level(ScanPage.value(legacy, :description).lines.first.to_s.delete_prefix(LEGACY_AI_PREFIX)) : overall_level
  end

  # An AI finding stored before rules version 4, whose description starts
  # "Risk Level: <Level>". AI findings in the current format are not.
  def legacy_ai?(finding)
    description = ScanPage.value(finding, :description)
    ScanPage::FindingGroups.ai?(finding) && description.is_a?(String) && description.start_with?(LEGACY_AI_PREFIX)
  end

  def level(value)
    return nil unless value.is_a?(String)

    name = value.strip.capitalize
    LEVELS.include?(name) ? name : nil
  end

  # Scans whose display level is `level`, as SQL over the JSON column. The
  # same rule as .for, except that SQL compares the stored severity and the
  # description exactly, where Ruby ignores case and spaces. An unknown
  # level matches nothing.
  def where_level(scope, level)
    return scope.none unless LEVELS.include?(level)

    findings = "jsonb_array_elements(CASE WHEN jsonb_typeof(security_findings) = 'array' " \
               "THEN security_findings ELSE '[]'::jsonb END)"
    overall = "jsonb_typeof(finding) = 'object' AND LOWER(finding->>'title') LIKE '%overall risk%'"
    verdict = "#{overall} AND (CASE WHEN jsonb_typeof(finding->'rules_version') = 'number' " \
              "AND finding->>'rules_version' ~ '^[0-9]{1,9}$' THEN (finding->>'rules_version')::int ELSE 1 END) >= #{VERDICT_VERSION.to_i}"
    legacy_ai = "jsonb_typeof(finding) = 'object' AND finding->>'title' = 'AI Context Analysis' " \
                "AND finding->>'severity' = 'Info' AND finding->>'description' LIKE '#{LEGACY_AI_PREFIX}%'"

    scope.where(<<~SQL.squish, level: level, legacy_level: "#{LEGACY_AI_PREFIX} #{level}")
      (
        EXISTS (SELECT 1 FROM #{findings} AS finding WHERE #{verdict} AND finding->>'severity' = :level)
      ) OR (
        NOT EXISTS (SELECT 1 FROM #{findings} AS finding WHERE #{verdict})
        AND EXISTS (
          SELECT 1 FROM #{findings} AS finding
          WHERE #{legacy_ai} AND split_part(finding->>'description', E'\\n', 1) = :legacy_level
        )
      ) OR (
        NOT EXISTS (SELECT 1 FROM #{findings} AS finding WHERE #{verdict})
        AND NOT EXISTS (SELECT 1 FROM #{findings} AS finding WHERE #{legacy_ai})
        AND EXISTS (SELECT 1 FROM #{findings} AS finding WHERE #{overall} AND finding->>'severity' = :level)
      )
    SQL
  end
end
