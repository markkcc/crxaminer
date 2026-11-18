require "test_helper"

class ExtensionAnalyzerOptionalHostsTest < ActiveSupport::TestCase
  def extract(manifest)
    buffer = Zip::OutputStream.write_buffer do |zip|
      zip.put_next_entry("manifest.json")
      zip.write(JSON.generate(manifest))
    end
    ExtensionAnalyzer.new(SecureRandom.hex(16)).send(:extract_manifest, buffer.string)
  end

  test "optional_host_permissions is extracted, and the engine rates it with evidence into raw" do
    result = extract("manifest_version" => 3, "name" => "X", "version" => "1",
                     "optional_host_permissions" => ["https://*/*"])
    assert_equal ["https://*/*"], result[:optional_host_permissions]

    finding = ExtensionSecurityAnalyzer.rule_findings(result).find { |f| f[:rule] == "optional.host.all_sites" }
    assert_equal [["optional_host_permissions", 0]], finding[:evidence]
    assert_equal "https://*/*", result[:raw].dig("optional_host_permissions", 0)
  end

  test "a manifest without it gets an empty list" do
    assert_equal [], extract("manifest_version" => 3, "name" => "X", "version" => "1")[:optional_host_permissions]
  end
end
