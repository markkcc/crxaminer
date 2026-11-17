module ScanPage
  # The raw manifest pretty-printed as JSON, one line at a time with token
  # classes for highlighting, plus where each key and array entry sits so a
  # finding can point at the lines that produced it.
  #
  # Tokens are plain text with Rouge's CSS class names (so rouge.css styles
  # them); the view escapes them like any other value.
  class ManifestDocument
    Line = Struct.new(:number, :tokens, :groups, keyword_init: true) do
      def text
        tokens.map(&:last).join
      end
    end

    # A long array shown collapsed: its opening line stays visible.
    Group = Struct.new(:id, :first, :last, :size, keyword_init: true)

    COLLAPSE_OVER = 20
    INDENT = "  ".freeze
    RISKY_HOST_PATTERNS = ExtensionAnalyzerData::RISKY_HOST_PATTERNS
    PERMISSION_TITLE = FindingGroups::PERMISSION_TITLE
    COMBINATION_PREFIX = FindingGroups::COMBINATION_PREFIX

    attr_reader :lines, :groups

    def initialize(raw)
      @raw = raw
      @lines = []
      @groups = []
      @ranges = {}
      @open_groups = []
      return if raw.nil? || (raw.respond_to?(:empty?) && raw.empty?)

      walk(raw, 0, [], [], false)
    end

    def empty?
      lines.empty?
    end

    def text
      lines.map(&:text).join("\n")
    end

    # First line of the value at a path such as ["permissions", 3].
    def line_of(path)
      @ranges[path]&.first
    end

    # Line numbers for a finding title, following the rule that produced it.
    # Where the rule cannot be traced to entries, this points at the key; for
    # titles it does not know, it returns nothing rather than guess.
    def lines_for(title)
      title = title.to_s
      if (name = title[PERMISSION_TITLE, 1])
        entry_lines("permissions") { |v| v == name }
      elsif title.start_with?(COMBINATION_PREFIX)
        names = title.delete_prefix(COMBINATION_PREFIX).split("+").map(&:strip)
        entry_lines("permissions") { |v| names.include?(v) }
      else
        case title
        when "Broad Host Permissions"
          entry_lines("host_permissions") { |v| v.is_a?(String) && RISKY_HOST_PATTERNS.any? { |r| v.include?(r) } }
        when "Access to Sensitive Domains"
          # The domain list lives inside the rule, not in a shared constant.
          key_lines("host_permissions")
        when "Broad Content Script Injection" then content_script_lines
        when "Older Manifest Version" then key_lines("manifest_version")
        when "Unsafe WebAssembly Execution" then csp_lines("'wasm-unsafe-eval'")
        when "Unsafe JavaScript Evaluation" then csp_lines("'unsafe-eval'")
        else []
        end
      end
    end

    private

    # Mirrors JSON.pretty_generate's layout, recording line ranges per path.
    def walk(value, depth, path, prefix, comma)
      start = @lines.size + 1
      case value
      when Hash
        if value.empty?
          add_line(depth, prefix + [["p", "{}"]], comma)
        else
          add_line(depth, prefix + [["p", "{"]], false)
          value.each_with_index do |(key, child), index|
            key = key.to_s
            walk(child, depth + 1, path + [key], [["nl", scalar(key)], ["p", ":"], [nil, " "]], index < value.size - 1)
          end
          add_line(depth, [["p", "}"]], comma)
        end
      when Array
        if value.empty?
          add_line(depth, prefix + [["p", "[]"]], comma)
        else
          add_line(depth, prefix + [["p", "["]], false)
          group = open_group(start, value.size) if value.size > COLLAPSE_OVER
          value.each_with_index do |child, index|
            walk(child, depth + 1, path + [index], [], index < value.size - 1)
          end
          close_group(group) if group
          add_line(depth, [["p", "]"]], comma)
        end
      else
        add_line(depth, prefix + [[token_class(value), scalar(value)]], comma)
      end
      @ranges[path] = start..@lines.size
    end

    def add_line(depth, tokens, comma)
      tokens = [[nil, INDENT * depth]] + tokens if depth.positive?
      tokens += [["p", ","]] if comma
      @lines << Line.new(number: @lines.size + 1, tokens: tokens, groups: @open_groups.map(&:id))
    end

    def open_group(opening_line, size)
      group = Group.new(id: "manifest-group-#{@groups.size + 1}", first: opening_line, size: size)
      @groups << group
      @open_groups.push(group)
      group
    end

    def close_group(group)
      @open_groups.pop
      group.last = @lines.size + 1 # the closing bracket, which stays visible
    end

    def scalar(value)
      case value
      when String, Integer, Float, true, false, nil then JSON.generate(value)
      else JSON.generate(value.to_s)
      end
    rescue StandardError
      # Invalid bytes cannot be JSON; show them as replacement characters.
      JSON.generate(value.to_s.dup.force_encoding(Encoding::UTF_8).scrub)
    end

    def token_class(value)
      case value
      when String then "s2"
      when Integer then "mi"
      when Float then "mf"
      when true, false, nil then "kc"
      else "s2"
      end
    end

    def top(key)
      ScanPage.value(@raw, key)
    end

    def key_lines(key)
      [line_of([key])].compact
    end

    def entry_lines(key)
      entries = top(key)
      return key_lines(key) unless entries.is_a?(Array)

      found = entries.each_index.select { |i| yield entries[i] }.filter_map { |i| line_of([key, i]) }
      found.empty? ? key_lines(key) : found
    end

    def content_script_lines
      scripts = top("content_scripts")
      return key_lines("content_scripts") unless scripts.is_a?(Array)

      found = scripts.each_with_index.flat_map do |script, i|
        matches = ScanPage.value(script, :matches)
        next [] unless matches.is_a?(Array)

        matches.each_index.select { |j| RISKY_HOST_PATTERNS.include?(matches[j]) }
          .filter_map { |j| line_of(["content_scripts", i, "matches", j]) }
      end
      found.empty? ? key_lines("content_scripts") : found
    end

    # The scanner stores a CSP object as "key: value" strings; match the same.
    def csp_lines(token)
      csp = top("content_security_policy")
      return key_lines("content_security_policy") unless csp.is_a?(Hash)

      found = csp.filter_map do |key, value|
        line_of(["content_security_policy", key.to_s]) if "#{key}: #{value}".include?(token)
      end
      found.empty? ? key_lines("content_security_policy") : found
    end
  end
end
