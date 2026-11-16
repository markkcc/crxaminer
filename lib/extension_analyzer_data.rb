module ExtensionAnalyzerData
  HIGH_RISK_PERMISSIONS = {
    "tabs" => "Can access browser tab information and manipulate tabs",
    "webRequest" => "Can intercept and modify web requests",
    "webRequestBlocking" => "Can block and modify web requests in real-time",
    "<all_urls>" => "Can access all websites and their content",
    "cookies" => "Can access and modify browser cookies",
    "history" => "Can access your browsing history",
    "management" => "Can manage other extensions",
    "proxy" => "Can control proxy settings",
    "webNavigation" => "Can track your web navigation",
    "downloads" => "Can download files and access download history",
    "clipboardWrite" => "Can modify clipboard content",
    "clipboardRead" => "Can read clipboard content",
    "bookmarks" => "Can access and modify bookmarks",
    "debugger" => "Can debug and manipulate other extensions/apps",
    "privacy" => "Can modify privacy settings",
    "identity" => "Can access your identity information"
  }.freeze

  MEDIUM_RISK_PERMISSIONS = {
    "storage" => "Can store data locally",
    "geolocation" => "Can access your location",
    "notifications" => "Can show notifications",
    "unlimitedStorage" => "Can store unlimited data locally",
    "activeTab" => "Can access the active tab when clicking the extension icon",
    "contextMenus" => "Can add items to the context menu",
    "webview" => "Can embed web content in the extension"
  }.freeze

  RISKY_HOST_PATTERNS = [
    "*://*/*",      # All URLs
    "<all_urls>",   # All URLs
    "*://*",        # All URLs
    "file:///*",    # Local file access
    "*"             # Wildcard
  ].freeze

  # The one severity palette. The colours are theme tokens defined in
  # app/assets/tailwind/application.css; read these through
  # ScanHelper#severity_classes rather than directly.
  SEVERITY_COLORS = {
    "Critical" => "bg-severity-critical text-severity-critical-fg",
    "High" => "bg-severity-high text-severity-high-fg",
    "Medium" => "bg-severity-medium text-severity-medium-fg",
    "Low" => "bg-severity-low text-severity-low-fg",
    "Minimal" => "bg-severity-minimal text-severity-minimal-fg",
    "Info" => "bg-severity-info text-severity-info-fg"
  }.freeze

  # Used for a level the palette does not know (for example a missing verdict).
  SEVERITY_FALLBACK_COLOR = "bg-gray-600 text-white".freeze

  SEVERITY_ORDER = {
    'critical' => 0,
    'high' => 1,
    'medium' => 2,
    'low' => 3,
    'minimal' => 4,
    'info' => 5
  }.freeze
end 