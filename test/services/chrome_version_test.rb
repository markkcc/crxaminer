require "test_helper"

class ChromeVersionTest < ActiveSupport::TestCase
  def with_env(value)
    original = ENV[ChromeVersion::ENV_VAR]
    value.nil? ? ENV.delete(ChromeVersion::ENV_VAR) : ENV[ChromeVersion::ENV_VAR] = value
    yield
  ensure
    original.nil? ? ENV.delete(ChromeVersion::ENV_VAR) : ENV[ChromeVersion::ENV_VAR] = original
  end

  test "defaults to Chrome 157 for prodversion and the User-Agent" do
    with_env(nil) do
      assert_equal "157.0", ChromeVersion.prodversion
      assert_includes ChromeVersion.user_agent, " Chrome/157.0.0.0 "
      assert_includes ExtensionAnalyzer.crx_download_url("a" * 32), "prodversion=157.0&"
    end
  end

  test "CHROME_PRODVERSION overrides the version everywhere" do
    with_env("158") do
      assert_equal "158.0", ChromeVersion.prodversion
      assert_includes ChromeVersion.user_agent, " Chrome/158.0.0.0 "
      assert_includes ExtensionAnalyzer.crx_download_url("a" * 32), "prodversion=158.0&"
    end
    with_env(" 158.0.8200.10 ") do
      assert_equal "158.0.8200.10", ChromeVersion.prodversion
      assert_includes ChromeVersion.user_agent, " Chrome/158.0.0.0 "
    end
  end

  test "an override of the wrong shape falls back to the default" do
    ["", "abc", "7", "157.0&x=1", "157..0", "-1", "157.0.0.0.0", "15700000", "157 0"].each do |junk|
      with_env(junk) do
        assert_equal ChromeVersion::DEFAULT, ChromeVersion.prodversion, junk.inspect
        assert_includes ChromeVersion.user_agent, " Chrome/157.0.0.0 ", junk.inspect
      end
    end
  end

  test "the download URL keeps its other parameters" do
    with_env(nil) do
      assert_equal "https://clients2.google.com/service/update2/crx?response=redirect&prodversion=157.0&" \
                   "acceptformat=crx2,crx3&x=id%3D#{'b' * 32}%26installsource%3Dondemand%26uc",
                   ExtensionAnalyzer.crx_download_url("b" * 32)
    end
  end
end
