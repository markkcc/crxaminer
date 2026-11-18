module ScanPage
  # The raw manifest pretty-printed as JSON, one line at a time with token
  # classes for highlighting, plus where each key and array entry sits so a
  # finding can point at the lines that produced it.
  #
  # Tokens are plain text with a short class name each, styled by the
  # manifest viewer rules in application.css: "k" object key, "s" string,
  # "n" number, "l" true/false/null, "p" punctuation, nil for indentation.
  # The view escapes them like any other value.
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

    # The rule engine that wrote findings before they carried evidence paths
    # (every scan stored before evidence existed). legacy_lines_for finds
    # lines from those findings' titles, so these copies describe that old
    # engine and must not follow changes to the current one.
    LEGACY_RISKY_HOST_PATTERNS = ["*://*/*", "<all_urls>", "*://*", "file:///*", "*"].freeze
    LEGACY_PERMISSION_TITLE = /\A\w+-Risk Permission: (.+)\z/m
    LEGACY_COMBINATION_PREFIX = "Dangerous Permission Combination:".freeze

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

    # The line for an evidence path, or for its nearest parent that exists
    # when the path does not resolve (the manifest changed shape, or an index
    # is out of range). The top-level object itself is never the answer:
    # pointing at its opening brace would tell the reader nothing.
    def resolve(path)
      return nil unless path.is_a?(Array)

      path.size.downto(1) do |size|
        line = line_of(path.first(size))
        return line if line
      end
      nil
    end

    # Line numbers for a finding stored without evidence, from its title and
    # the old engine's rules (see LEGACY_*). Where the rule cannot be traced
    # to entries, this points at the key; for titles it does not know, it
    # returns nothing rather than guess.
    def legacy_lines_for(title)
      title = title.to_s
      if (name = title[LEGACY_PERMISSION_TITLE, 1])
        entry_lines("permissions") { |v| v == name }
      elsif title.start_with?(LEGACY_COMBINATION_PREFIX)
        names = title.delete_prefix(LEGACY_COMBINATION_PREFIX).split("+").map(&:strip)
        entry_lines("permissions") { |v| names.include?(v) }
      else
        case title
        when "Broad Host Permissions"
          entry_lines("host_permissions") { |v| v.is_a?(String) && LEGACY_RISKY_HOST_PATTERNS.any? { |r| v.include?(r) } }
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
            walk(child, depth + 1, path + [key], [["k", scalar(key)], ["p", ":"], [nil, " "]], index < value.size - 1)
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
      when Integer, Float then "n"
      when true, false, nil then "l"
      else "s"
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

        matches.each_index.select { |j| LEGACY_RISKY_HOST_PATTERNS.include?(matches[j]) }
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
