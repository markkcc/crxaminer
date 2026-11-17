# The Chrome version CRXaminer reports to Google: the `prodversion` of the CRX
# download URL and the User-Agent of every request to the Chrome Web Store and
# the update server. The update server answers 204 (no download) for some
# extensions when the reported version is older than they require, so this
# has to follow Chrome stable.
#
# CHROME_PRODVERSION overrides the default without a deploy (for example
# "158" or "158.0.8200.10"). A value of the wrong shape is ignored.
module ChromeVersion
  DEFAULT = "157.0".freeze
  ENV_VAR = "CHROME_PRODVERSION".freeze
  FORMAT = /\A\d{2,4}(?:\.\d{1,6}){0,3}\z/

  class << self
    # "157.0", or the override with ".0" appended when it is a bare major.
    def prodversion
      raw = ENV[ENV_VAR].to_s.strip
      return DEFAULT if raw.empty?

      unless raw.match?(FORMAT)
        Rails.logger.warn "Ignoring #{ENV_VAR}=#{raw.truncate(20).inspect}: expected a version like 157 or 157.0.8103.78"
        return DEFAULT
      end
      raw.include?(".") ? raw : "#{raw}.0"
    end

    def major
      prodversion.split(".").first
    end

    # Chrome's reduced User-Agent: only the major version is real.
    def user_agent
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) " \
        "Chrome/#{major}.0.0.0 Safari/537.36"
    end
  end
end
