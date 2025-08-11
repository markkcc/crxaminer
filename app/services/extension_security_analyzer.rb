class ExtensionSecurityAnalyzer
  include ExtensionAnalyzerData
  
  def initialize(manifest, extension_details = nil, extension_name = nil, extension_id = nil)
    @manifest = manifest
    @extension_details = extension_details
    @extension_name = extension_name
    @extension_id = extension_id
    @security_findings = []
    begin
      @client = Anthropic::Client.new
    rescue => e
      Rails.logger.error "Failed to initialize Anthropic client: #{e.message}"
      Rails.logger.error e.backtrace.join("\n")
      @client = nil
    end
  end

  def analyze
    return [] unless @manifest
    
    analyze_security_risks
    analyze_with_claude
    tweet_results
    @security_findings
  end

  private

  def analyze_security_risks
    analyze_permission_risks
    analyze_host_permission_risks
    analyze_content_script_risks
    analyze_manifest_version_risks
    analyze_csp_risks
    calculate_overall_risk
  end

  def analyze_permission_risks
    @manifest[:permissions].each do |permission|
      if HIGH_RISK_PERMISSIONS.key?(permission)
        add_finding("High", "High-Risk Permission: #{permission}",
          "This extension has the #{permission} permission. #{HIGH_RISK_PERMISSIONS[permission]}. " +
          "This could potentially be used maliciously to compromise security or privacy.")
      elsif MEDIUM_RISK_PERMISSIONS.key?(permission)
        add_finding("Medium", "Medium-Risk Permission: #{permission}",
          "This extension has the #{permission} permission. #{MEDIUM_RISK_PERMISSIONS[permission]}.")
      end
    end

    has_web_request = @manifest[:permissions].include?("webRequest")
    has_web_request_blocking = @manifest[:permissions].include?("webRequestBlocking")
    if has_web_request && has_web_request_blocking
      add_finding("High", "Dangerous Permission Combination: webRequest + webRequestBlocking",
        "This extension can intercept, modify, and block web requests in real-time. " +
        "This combination could be used to modify sensitive web traffic or steal data.")
    end
  end

  def analyze_host_permission_risks
    broad_host_permissions = @manifest[:host_permissions]&.any? do |pattern|
      RISKY_HOST_PATTERNS.any? { |risky| pattern.include?(risky) }
    end

    if broad_host_permissions
      add_finding("High", "Broad Host Permissions",
        "This extension has broad host permissions allowing it to access many or all websites. " +
        "This could potentially be used to steal sensitive data or track browsing activity.")
    end

    sensitive_domains = @manifest[:host_permissions]&.select do |pattern|
      # Major Banks
      pattern.include?("chase") || pattern.include?("bankofamerica") || pattern.include?("wellsfargo") ||
      pattern.include?("citibank") || pattern.include?("capitalone") || pattern.include?("usbank") ||
      pattern.include?("barclays") || pattern.include?("hsbc") || pattern.include?("santander") ||
      pattern.include?("rbcroyalbank") || pattern.include?("scotiabank") || pattern.include?("tdbank") ||
      
      # Financial Services
      pattern.include?("paypal") || pattern.include?("venmo") || pattern.include?("wise") ||
      pattern.include?("stripe") || pattern.include?("square") || pattern.include?("cashapp") ||
      pattern.include?("revolut") || pattern.include?("robinhood") || pattern.include?("fidelity") ||
      pattern.include?("vanguard") || pattern.include?("schwab") || pattern.include?("etrade") ||
      
      # Crypto Exchanges & Wallets
      pattern.include?("coinbase") || pattern.include?("binance") || pattern.include?("kraken") ||
      pattern.include?("metamask") || pattern.include?("crypto.com") || pattern.include?("gemini") ||
      pattern.include?("ledger") || pattern.include?("trezor") || pattern.include?("blockchain.com") ||
      pattern.include?("ftx") || pattern.include?("kucoin") || pattern.include?("bitfinex") ||
      
      # Social Media & Email (high-value targets)
      pattern.include?("google") || pattern.include?("facebook") || pattern.include?("instagram") ||
      pattern.include?("twitter") || pattern.include?("linkedin") || pattern.include?("outlook") ||
      pattern.include?("protonmail") || pattern.include?("yahoo") || pattern.include?("gmail") ||
      
      # E-commerce & Payment
      pattern.include?("amazon") || pattern.include?("shopify") || pattern.include?("ebay") ||
      pattern.include?("walmart") || pattern.include?("bestbuy") || pattern.include?("target") ||
      
      # Code Repositories & Development
      pattern.include?("github") || pattern.include?("gitlab") || pattern.include?("bitbucket") ||
      pattern.include?("stackoverflow") || pattern.include?("npmjs") || pattern.include?("pypi") ||
      
      # CI/CD & Package Management
      pattern.include?("circleci") || pattern.include?("jenkins") || pattern.include?("travis-ci") ||
      pattern.include?("dockerhub") || pattern.include?("nuget") || pattern.include?("maven") ||
      pattern.include?("rubygems") || pattern.include?("packagist") || pattern.include?("crates.io") ||
      
      # Generic Financial Terms
      pattern.include?("banking") || pattern.include?("invest") || pattern.include?("wallet") ||
      pattern.include?("finance") || pattern.include?("credit") || pattern.include?("debit") ||
      pattern.include?("bank") || pattern.include?("crypto")
    end

    if sensitive_domains&.any?
      add_finding("Medium", "Access to Sensitive Domains",
        "This extension requests access to sensitive domains: #{sensitive_domains.join(', ')}. " +
        "Ensure you trust this extension with access to these sites.")
    end
  end

  def analyze_content_script_risks
    if @manifest[:content_scripts]&.any?
      broad_matches = @manifest[:content_scripts].any? do |script|
        script['matches']&.any? { |match| RISKY_HOST_PATTERNS.include?(match) }
      end

      if broad_matches
        add_finding("High", "Broad Content Script Injection",
          "This extension can inject scripts into any website. This means it could potentially " +
          "read sensitive data, modify website content, or steal credentials.")
      end
    end
  end

  def analyze_manifest_version_risks
    if @manifest[:manifest_version].to_i < 3
      add_finding("Medium", "Older Manifest Version",
        "This extension uses Manifest Version #{@manifest[:manifest_version]}, which has fewer " +
        "security restrictions than Manifest V3. Consider using extensions that have upgraded to V3.")
    end
  end

  def analyze_csp_risks
    
    csp_array = Array(@manifest[:content_security_policy])
    if csp_array.any? { |policy| policy.include?("'wasm-unsafe-eval'") }
      add_finding("High", "Unsafe WebAssembly Execution",
        "This extension's Content Security Policy allows 'wasm-unsafe-eval', which permits " +
        "potentially dangerous WebAssembly code execution. This could be used to hide malicious " +
        "code or perform CPU-intensive operations.")
    elsif csp_array.any? { |policy| policy.include?("'unsafe-eval'") }
      add_finding("High", "Unsafe JavaScript Evaluation",
        "This extension's Content Security Policy allows 'unsafe-eval', which permits " +
        "dynamic JavaScript code execution using eval() and similar functions. This is a " +
        "significant security risk as it could allow execution of malicious code.")
    end
  end

  def add_finding(severity, title, description)
    @security_findings << {
      severity: severity,
      title: title,
      description: description
    }
  end

  def calculate_overall_risk
    high_findings = @security_findings.count { |f| f[:severity] == "High" }
    medium_findings = @security_findings.count { |f| f[:severity] == "Medium" }
    
    overall_risk = if high_findings > 3
      "Critical"
    elsif high_findings > 1
      "High"
    elsif medium_findings > 1 || high_findings > 0
      "Medium"
    elsif medium_findings > 0
      "Low"
    else
      "Minimal"
    end

    @security_findings.unshift({
      severity: "#{overall_risk}",
      title: "Overall Risk: #{overall_risk}",
      description: "Based on #{@security_findings.size} total findings, ranked without considering overall context, including #{high_findings} high-risk and #{medium_findings} medium-risk findings."
    })
  end

  def analyze_with_claude
    begin
      return unless @client
      
      prompt = format_prompt
      
      response = @client.messages(
        parameters: {
          model: "claude-sonnet-4-20250514",
          system: "You are a security analysis tool called CRXaminer that assesses Chrome Extensions for risk. Given metrics that are visible to the user, analyze the risk of the chrome extension, and provide a short summary under 200 words adding context to the findings that the user can already see (do not repeat the extension's permissions). Some example recommendations include: If an extension is very high risk, the user can run it in a separate chrome profile. The response should be formatted as follows: Include your own risk level (Critical, High, Medium, Low, or Minimal). include trust factors based on the extension's description, downloads, company reputation, etc. include a list of concerns, including unnecessary permissions given the nature of the extension etc. finally include some recommendations. Important note: Do not format the response in markdown, do not use any asterisk characters for bold.",
          messages: [
            {
              role: "user",
              content: prompt
            }
          ],
          max_tokens: 400,
          temperature: 0.3
        }
      )

      response_text = response["content"].first["text"]

      add_finding(
        "Info",
        "AI Context Analysis",
        response_text
      )
    rescue => e
      Rails.logger.error "AI analysis failed: #{e.message}"
    end
  end

  def format_prompt

    prompt = """
    Analyze this Chrome extension:
  
    Extension Details:
    Name: #{@extension_name}
    Version: #{@manifest[:version]}
    Description: #{@manifest[:description]}
    Manifest Version: #{@manifest[:manifest_version]}
    Size: #{@extension_details[:size]}
    Users: #{@extension_details[:users]}
    Last Updated: #{@extension_details[:last_updated]}
    Rating: #{@extension_details[:rating]} (#{@extension_details[:rating_count]} reviews)
    Author: #{@extension_details[:author]}
    Developer Info: #{@extension_details[:developer_info]}
  
    Technical Details:
    Permissions: #{@manifest[:permissions].join(', ')}
    Host Permissions: #{@manifest[:host_permissions]&.join(', ')}
    Content Scripts: #{@manifest[:content_scripts]&.map { |cs| cs['matches']&.join(', ') }&.join('; ')}
    Background Scripts: #{@manifest[:background]&.[](:service_worker) || @manifest[:background]&.[](:scripts)&.join(', ')}
    Web Accessible Resources: #{@manifest[:web_accessible_resources]&.map { |r| r['resources']&.join(', ') }&.join('; ')}
    CSP: #{@manifest[:content_security_policy]}
  
    Security Findings:
    #{@security_findings.map { |f| 
      "#{f[:severity]}: #{f[:title]}\n#{f[:description].gsub(/https?:\/\/[^\s]+/, '[URL]')}"
    }.join("\n\n")}
    """

    prompt
  end

  def tweet_results
    tweet_text = format_tweet_text
    Rails.logger.info "#{tweet_text}"
    TwitterClient.new.post_tweet(tweet_text)
  rescue => e
    Rails.logger.error "Failed to tweet scan results: #{e.message}"
  end

  def format_tweet_text
    ai_analysis = @security_findings.find { |f| f[:severity] == "Info" && f[:title] == "AI Context Analysis" }
    
    risk_level = if ai_analysis&.[](:description)&.start_with?("Risk Level:")
      ai_analysis[:description].split("\n").first.split("Risk Level:").last&.strip
    else
      "N/A"
    end
    
    overall_risk = @security_findings.find { |f| f[:title]&.downcase&.include?('overall risk') }&.[](:severity) || "N/A"
    
    combined_risk = if risk_level == overall_risk
      "Risk: #{risk_level}"
    else
      "Risk: #{risk_level} / #{overall_risk}"
    end
  
    [
      @extension_name.presence || "Unknown Extension",
      "#{(@extension_details[:rating].present? && @extension_details[:rating_count].present?) ? 
        "#{@extension_details[:rating]} ★ (#{@extension_details[:rating_count]})" : "? ★"}, #{@extension_details[:size].presence || "?KiB"}",
      combined_risk,
      "https://crxaminer.tech/scan/#{@extension_id}"
    ].join("\n")
  rescue StandardError => e
    Rails.logger.error "Error formatting tweet text: #{e.message}"
    "Scan complete! https://crxaminer.tech/scan/#{@extension_id}"
  end

end 