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

  SEVERITY_COLORS = {
    "Critical" => "bg-violet-600 text-white",
    "High" => "bg-red-600 text-white",
    "Medium" => "bg-orange-500 text-white",
    "Low" => "bg-yellow-500 text-white",
    "Minimal" => "bg-green-500 text-white",
    "Info" => "bg-blue-500 text-white"
  }.freeze

  SEVERITY_ORDER = {
    'critical' => 0,
    'high' => 1,
    'medium' => 2,
    'low' => 3,
    'minimal' => 4,
    'info' => 5
  }.freeze
end 