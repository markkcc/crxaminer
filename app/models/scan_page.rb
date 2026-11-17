# Presentation logic for the scan results page. Everything here reads stored
# scan data only: about 20,000 rows were written by older versions of the
# scanner, so any key can be missing and any value can be any JSON type.
# These helpers never raise on such input.
module ScanPage
  module_function

  # Reads a key whether the hash was stored with symbol or string keys.
  def value(hash, key)
    return nil unless hash.is_a?(Hash)

    hash.key?(key.to_sym) ? hash[key.to_sym] : hash[key.to_s]
  end

  def list(value)
    value.is_a?(Array) ? value : []
  end

  def strings(value)
    list(value).grep(String)
  end

  # A stored value as display text; non-strings become their JSON form.
  def text(value)
    return value if value.is_a?(String)

    JSON.generate(value)
  rescue StandardError
    value.to_s
  end
end
