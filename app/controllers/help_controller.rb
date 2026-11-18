# The "how it works" page linked from the main navigation.
class HelpController < ApplicationController
  WRITE_UP_URL = "https://astarte.security/docs/tools/crxaminer".freeze

  # One row of the rating table: the rules and the permissions that put an
  # extension at this level.
  Level = Struct.new(:name, :rules, :permissions, keyword_init: true)

  # The table is built from the rule engine's own data, so it always matches
  # what the engine does. Optional items are explained in one sentence on the
  # page instead of being listed again.
  def show
    data = ExtensionAnalyzerData
    permissions = data.permissions_by_level
    @levels = data::LEVELS.map do |level|
      rules = data.rules.select { |rule| rule.severity == level && !rule.id.start_with?("optional.") }
      Level.new(name: level, rules: rules, permissions: permissions.fetch(level, []))
    end
  end
end
