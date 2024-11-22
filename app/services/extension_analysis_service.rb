class ExtensionAnalysisService
  include ExtensionAnalyzer
  
  def initialize(manifest)
    @manifest = manifest
    @security_findings = []
  end

  def analyze
    return [] unless @manifest
    
    analyze_security_risks
    @security_findings
  end

  private

  def analyze_security_risks
    analyze_permission_risks
    analyze_host_permission_risks
    analyze_content_script_risks
    analyze_manifest_version_risks
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
      description: "Based on #{high_findings} high-risk and #{medium_findings} medium-risk findings."
    })
  end
end 