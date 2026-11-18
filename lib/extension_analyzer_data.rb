# The data behind CRXaminer's rule-based rating, in one place: the levels,
# the rules, the permission ratings and the sensitive-site list. The rule
# engine (ExtensionSecurityAnalyzer), the scan page (ScanPage::*) and the
# "how we rate" page all read from here, so they cannot disagree.
#
# Read-only API for a help page:
#   ExtensionAnalyzerData::LEVELS                   finding levels, most severe first
#   ExtensionAnalyzerData::OVERALL_LEVELS           LEVELS plus "Minimal" (no findings)
#   ExtensionAnalyzerData.rules                     every rule, as Rule structs
#   ExtensionAnalyzerData.critical_combinations     the Critical rules only
#   ExtensionAnalyzerData.permissions_by_level      {"Critical" => [names], "High" => [...], ...}
#   ExtensionAnalyzerData.permission(name)          a Permission struct, or nil
#   ExtensionAnalyzerData.permission_level(name)    "High" etc., or nil when unknown
#   ExtensionAnalyzerData.optional_level(level)     the level of the same item when optional
#   ExtensionAnalyzerData.sensitive_sites           {"Banking" => [domains], ...}
module ExtensionAnalyzerData
  # Levels a finding can have, most severe first. The overall rating is the
  # highest level among the findings, or "Minimal" when there are none.
  LEVELS = %w[Critical High Medium Low].freeze
  OVERALL_LEVELS = (LEVELS + ["Minimal"]).freeze

  Rule = Struct.new(:id, :severity, :name, :summary, keyword_init: true)

  # Every rule the engine applies, keyed by the stable id stored on each
  # finding as `rule`. severity is nil where it depends on the permission.
  # Optional items (rules starting with "optional.") are rated one level
  # below the required one, never below Low and never Critical.
  RULES = [
    { id: "combination.all_sites_cookies", severity: "Critical", name: "All sites plus cookies",
      summary: "It can read the cookies that keep you signed in on every website, so it could take over your accounts." },
    { id: "combination.all_sites_web_request_blocking", severity: "Critical", name: "All sites plus blocking web requests",
      summary: "It can watch, block and change the traffic of every website while it happens." },
    { id: "permission", severity: nil, name: "Permission",
      summary: "Each permission it asks for at install is rated from the permission table (debugger is Critical)." },
    { id: "host.all_sites", severity: "High", name: "Access to all websites",
      summary: "It can read and change every website you visit, including sites where you are signed in." },
    { id: "content_script.all_sites", severity: "High", name: "Scripts on all websites",
      summary: "Its scripts run automatically in every website you open." },
    { id: "csp.unsafe_eval", severity: "High", name: "'unsafe-eval' in its pages' policy",
      summary: "Its own pages may turn text into code and run it, which makes unreviewed code easier to run." },
    { id: "host.sensitive", severity: "Medium", name: "Access to sensitive sites",
      summary: "It asks for access to named sites such as banks, payment services, email or code hosting." },
    { id: "host.file", severity: "Low", name: "Access to local files",
      summary: "It can read files on your computer, but only if you turn on file access for it." },
    { id: "csp.wasm_unsafe_eval", severity: "Low", name: "WebAssembly allowed",
      summary: "Its pages may run WebAssembly; this is the standard way to do so in Manifest V3." },
    { id: "manifest.v2", severity: "Low", name: "Manifest V2",
      summary: "It uses the older Manifest V2 format, which has fewer restrictions and is being phased out." },
    { id: "optional.permission", severity: nil, name: "Optional permission",
      summary: "A permission it can ask for later; Chrome asks you first. Rated one level below the same permission at install." },
    { id: "optional.host.all_sites", severity: "Medium", name: "Optional access to all websites",
      summary: "It can ask for access to every website later; Chrome asks you first." },
    { id: "optional.host.sensitive", severity: "Low", name: "Optional access to sensitive sites",
      summary: "It can ask for access to sensitive sites later; Chrome asks you first." },
    { id: "optional.host.file", severity: "Low", name: "Optional access to local files",
      summary: "It can ask to read files on your computer later; Chrome asks you first." }
  ].map { |attrs| Rule.new(**attrs).freeze }.freeze

  RULE_IDS = RULES.map(&:id).freeze

  # The Critical combinations: the rule id and the API permissions that,
  # together with required access to all websites, trigger it. Only
  # permissions requested at install count.
  CRITICAL_COMBINATIONS = {
    "combination.all_sites_cookies" => %w[cookies],
    "combination.all_sites_web_request_blocking" => %w[webRequest webRequestBlocking]
  }.freeze

  Permission = Struct.new(:name, :level, :allows, :why, :doc_page, keyword_init: true)

  # Chrome's documented extension permissions:
  #   name => [level, what it allows, why it matters (nil for Low), API page]
  # "What it allows" completes "lets it ..." after lowercasing its first
  # letter. The API page is a path under
  # https://developer.chrome.com/docs/extensions/reference/api/, or nil for
  # the permissions list page. A name not in this table produces no finding.
  PERMISSION_TABLE = {
    "debugger" => ["Critical", "Attach Chrome's debugger to tabs, which gives full control over those pages",
                   "It can read and change anything in those pages, including passwords and sites where you are signed in.", "debugger"],

    "browsingData" => ["High", "Clear browsing data such as history, cookies and cache",
                       "It can delete your history and cookies, which signs you out of sites and can remove traces of what it did.", "browsingData"],
    "clipboardRead" => ["High", "Read what you copy to the clipboard",
                        "What you copy can include passwords and other private text.", nil],
    "contentSettings" => ["High", "Change per-site settings such as JavaScript, cookies, camera and microphone",
                          "It can let sites use your camera, microphone or location without asking you.", "contentSettings"],
    "desktopCapture" => ["High", "Capture the screen, a window or a tab, after you pick one",
                         "Anything shown on what you share can be recorded, including private information.", "desktopCapture"],
    "history" => ["High", "Read and change your browsing history",
                  "Your history lists every site you have visited.", "history"],
    "management" => ["High", "List, turn on or off, and uninstall your other extensions and apps",
                     "It can turn off other extensions, including security tools.", "management"],
    "nativeMessaging" => ["High", "Exchange messages with programs installed on your computer",
                          "Programs outside the browser are not limited by Chrome's protections.", nil],
    "privacy" => ["High", "Change privacy-related browser settings",
                  "It can turn off protections such as Safe Browsing or limits on third-party cookies.", "privacy"],
    "proxy" => ["High", "Choose the proxy server that your browser traffic goes through",
                "All your browsing can be sent through a server it chooses, which can see which sites you visit.", "proxy"],
    "tabCapture" => ["High", "Record the video and audio of a tab",
                     "What you see and hear in a tab can be recorded, including private information.", "tabCapture"],
    "webAuthenticationProxy" => ["High", "Answer Web Authentication requests on behalf of sites (remote desktop)",
                                 "Sign-ins with security keys or passkeys go to the extension instead of your device.", "webAuthenticationProxy"],
    "webNavigation" => ["High", "See the address of each page as you navigate",
                        "It can follow every page you visit, as you visit it.", "webNavigation"],

    "bookmarks" => ["Medium", "Read and change your bookmarks",
                    "Bookmarks reveal the sites you use and your interests.", "bookmarks"],
    "clipboardWrite" => ["Medium", "Write to the clipboard",
                         "It can replace what you copied, for example a payment address.", nil],
    "cookies" => ["Medium", "Read and change cookies for the sites it has access to",
                  "Cookies keep you signed in; whoever has them can act as you on that site.", "cookies"],
    "declarativeNetRequest" => ["Medium", "Block or change network requests using rules it declares",
                                "Its rules can block pages or send you somewhere else.", "declarativeNetRequest"],
    "declarativeNetRequestWithHostAccess" => ["Medium", "Block or change network requests with declared rules, on sites it has access to",
                                              "Its rules can block pages or send you somewhere else.", "declarativeNetRequest"],
    "downloads" => ["Medium", "Start downloads and read and change your download history",
                    "It can save files to your computer and see what you downloaded.", "downloads"],
    "downloads.open" => ["Medium", "Open downloaded files",
                         "Opening a downloaded file can start a program on your computer.", "downloads"],
    "geolocation" => ["Medium", "Use your location without asking each time",
                      "Your location can reveal where you live or work.", nil],
    "identity" => ["Medium", "Sign you in to services through OAuth",
                   "With your approval it can use your accounts, such as your Google account, through their APIs.", "identity"],
    "identity.email" => ["Medium", "Read the email address of the signed-in Chrome profile",
                         "Your email address identifies you.", "identity"],
    "input" => ["Medium", "Act as a keyboard or input method (ChromeOS)",
                "An input method sees what you type with it.", "input/ime"],
    "pageCapture" => ["Medium", "Save pages as MHTML files",
                      "Saved pages include whatever private information they show.", "pageCapture"],
    "readingList" => ["Medium", "Read and change your reading list",
                      "Your reading list shows pages you chose to keep.", "readingList"],
    "scripting" => ["Medium", "Run scripts and add styles in pages it has access to",
                    "A script in a page can read and change that page.", "scripting"],
    "sessions" => ["Medium", "Read and restore recently closed tabs and windows, including from your other devices",
                   "It can see tabs from your other signed-in devices.", "sessions"],
    "tabs" => ["Medium", "See the address and title of every open tab",
               "The addresses of your open tabs show what you are browsing.", "tabs"],
    "topSites" => ["Medium", "Read your most visited sites",
                   "Your most visited sites reveal your habits.", "topSites"],
    "userScripts" => ["Medium", "Run user scripts that it manages in pages",
                      "It can run scripts in pages that were not part of the extension Chrome reviewed.", "userScripts"],
    "vpnProvider" => ["Medium", "Provide a VPN (ChromeOS)",
                      "Your network traffic can go through its VPN.", "vpnProvider"],
    "webRequest" => ["Medium", "Watch network requests to the sites it has access to",
                     "It can see where your browser connects on those sites.", "webRequest"],
    "webRequestAuthProvider" => ["Medium", "Answer sign-in prompts for HTTP authentication",
                                 "It can answer password prompts from websites on your behalf.", "webRequest"],
    "webRequestBlocking" => ["Medium", "Block or change network requests while they happen",
                             "It can block or change the traffic of the sites it has access to.", "webRequest"],

    "accessibilityFeatures.modify" => ["Low", "Change accessibility settings", nil, "accessibilityFeatures"],
    "accessibilityFeatures.read" => ["Low", "Read accessibility settings", nil, "accessibilityFeatures"],
    "activeTab" => ["Low", "Use the current tab, only after you click the extension or choose one of its menu items or shortcuts", nil, nil],
    "alarms" => ["Low", "Schedule its own code to run at set times", nil, "alarms"],
    "audio" => ["Low", "Read and control audio devices (ChromeOS)", nil, "audio"],
    "background" => ["Low", "Keep running in the background after Chrome's windows are closed (legacy)", nil, nil],
    "certificateProvider" => ["Low", "Provide client certificates to ChromeOS", nil, "certificateProvider"],
    "contextMenus" => ["Low", "Add items to the right-click menu", nil, "contextMenus"],
    "declarativeContent" => ["Low", "Show its button depending on page content, without reading the page", nil, "declarativeContent"],
    "declarativeNetRequestFeedback" => ["Low", "See which of its request rules matched", nil, "declarativeNetRequest"],
    "dns" => ["Low", "Look up host names", nil, "dns"],
    "documentScan" => ["Low", "Use document scanners (ChromeOS)", nil, "documentScan"],
    "downloads.shelf" => ["Low", "Change the downloads bar (legacy)", nil, "downloads"],
    "downloads.ui" => ["Low", "Change the downloads bubble", nil, "downloads"],
    "enterprise.deviceAttributes" => ["Low", "Read device attributes on managed ChromeOS devices", nil, "enterprise/deviceAttributes"],
    "enterprise.hardwarePlatform" => ["Low", "Read the hardware maker and model on managed devices", nil, "enterprise/hardwarePlatform"],
    "enterprise.networkingAttributes" => ["Low", "Read network details on managed ChromeOS devices", nil, "enterprise/networkingAttributes"],
    "enterprise.platformKeys" => ["Low", "Use enterprise certificates on managed ChromeOS devices", nil, "enterprise/platformKeys"],
    "favicon" => ["Low", "Show the icons of websites", nil, nil],
    "fileBrowserHandler" => ["Low", "Handle files in the ChromeOS Files app", nil, "fileBrowserHandler"],
    "fileSystemProvider" => ["Low", "Provide file systems to the ChromeOS Files app", nil, "fileSystemProvider"],
    "fontSettings" => ["Low", "Read and change Chrome's font settings", nil, "fontSettings"],
    "gcm" => ["Low", "Receive push messages through Firebase Cloud Messaging", nil, "gcm"],
    "idle" => ["Low", "Detect when the computer is idle or locked", nil, "idle"],
    "loginState" => ["Low", "Read whether you are signed in (ChromeOS)", nil, "loginState"],
    "notifications" => ["Low", "Show system notifications", nil, "notifications"],
    "offscreen" => ["Low", "Open hidden pages to use web APIs in the background", nil, "offscreen"],
    "platformKeys" => ["Low", "Use client certificates managed by ChromeOS", nil, "platformKeys"],
    "power" => ["Low", "Keep the computer or display awake", nil, "power"],
    "printerProvider" => ["Low", "Provide printers to Chrome's print dialog", nil, "printerProvider"],
    "printing" => ["Low", "Send print jobs to printers (ChromeOS)", nil, "printing"],
    "printingMetrics" => ["Low", "Read printing history on managed ChromeOS devices", nil, "printingMetrics"],
    "processes" => ["Low", "Read information about Chrome's processes", nil, "processes"],
    "search" => ["Low", "Run searches with your default search engine", nil, "search"],
    "sidePanel" => ["Low", "Show its own page in Chrome's side panel", nil, "sidePanel"],
    "storage" => ["Low", "Save data in the extension's own storage", nil, "storage"],
    "system.cpu" => ["Low", "Read processor information", nil, "system/cpu"],
    "system.display" => ["Low", "Read display information", nil, "system/display"],
    "system.memory" => ["Low", "Read memory information", nil, "system/memory"],
    "system.storage" => ["Low", "Read information about storage devices and eject removable ones", nil, "system/storage"],
    "tabGroups" => ["Low", "Read and change tab groups", nil, "tabGroups"],
    "tts" => ["Low", "Read text aloud with speech synthesis", nil, "tts"],
    "ttsEngine" => ["Low", "Provide a text-to-speech voice", nil, "ttsEngine"],
    "unlimitedStorage" => ["Low", "Store more data than the usual limit", nil, nil],
    "wallpaper" => ["Low", "Change the wallpaper (ChromeOS)", nil, "wallpaper"]
  }.freeze

  PERMISSIONS = PERMISSION_TABLE.to_h do |name, (level, allows, why, doc_page)|
    [name, Permission.new(name: name, level: level, allows: allows, why: why, doc_page: doc_page).freeze]
  end.freeze

  # Sites where access matters more than usual, as registrable domains
  # (the part you can register, such as "chase.com" or "barclays.co.uk").
  # A host matches when its registrable domain is in this list; subdomains
  # match too, look-alikes and substrings do not.
  SENSITIVE_SITES = {
    "Banking" => %w[
      chase.com bankofamerica.com wellsfargo.com citi.com citibank.com capitalone.com usbank.com pnc.com
      barclays.com barclays.co.uk hsbc.com hsbc.co.uk santander.com santander.co.uk lloydsbank.com natwest.com
      rbcroyalbank.com scotiabank.com td.com tdbank.com
    ],
    "Payments and investing" => %w[
      venmo.com wise.com transferwise.com stripe.com squareup.com cash.app revolut.com klarna.com
      robinhood.com fidelity.com vanguard.com schwab.com etrade.com
    ],
    "Crypto" => %w[
      coinbase.com binance.com kraken.com metamask.io crypto.com gemini.com ledger.com trezor.io
      blockchain.com kucoin.com bitfinex.com
    ],
    "Email and social" => %w[
      gmail.com outlook.com live.com hotmail.com office.com microsoftonline.com icloud.com proton.me protonmail.com
      facebook.com instagram.com twitter.com x.com linkedin.com
    ],
    "Shopping" => %w[shopify.com walmart.com bestbuy.com target.com],
    "Developer platforms" => %w[
      github.com gitlab.com bitbucket.org npmjs.com pypi.org rubygems.org crates.io nuget.org packagist.org
      docker.com circleci.com travis-ci.com
    ]
  }.transform_values(&:freeze).freeze

  # Brands that use many country domains (google.de, amazon.co.uk). These
  # match on the registrable domain's own label, whatever the public suffix:
  # "google" matches google.de but not googleapis.com or googleusercontent.com.
  SENSITIVE_BRANDS = {
    "google" => "Email and social",
    "yahoo" => "Email and social",
    "paypal" => "Payments and investing",
    "amazon" => "Shopping",
    "ebay" => "Shopping"
  }.freeze

  SENSITIVE_DOMAINS = SENSITIVE_SITES.flat_map { |category, domains| domains.map { |d| [d, category] } }.to_h.freeze

  # Legacy: the patterns the engine used before RULES_VERSION 2. Kept only so
  # code that reads findings stored by older versions keeps working; the
  # current engine uses MatchPattern instead.
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

  module_function

  def rules
    RULES
  end

  def rule(id)
    RULES.find { |r| r.id == id }
  end

  def critical_combinations
    RULES.select { |r| CRITICAL_COMBINATIONS.key?(r.id) }
  end

  def permission(name)
    name.is_a?(String) ? PERMISSIONS[name] : nil
  end

  def permission_level(name)
    permission(name)&.level
  end

  # Names per level, every level present (possibly empty), names sorted.
  def permissions_by_level
    LEVELS.to_h { |level| [level, PERMISSIONS.values.select { |p| p.level == level }.map(&:name).sort] }
  end

  # An optional item is rated one level below the required one, never below
  # Low; since Critical is reserved for required items, optional is never Critical.
  def optional_level(level)
    index = LEVELS.index(level)
    return nil unless index

    LEVELS[[index + 1, LEVELS.size - 1].min]
  end

  def sensitive_sites
    SENSITIVE_SITES.merge(SENSITIVE_BRANDS.group_by(&:last).transform_values { |pairs| pairs.map { |brand, _| "#{brand} (any country domain)" } }) do |_, a, b|
      a + b
    end
  end

  # The category of a registrable domain ("paypal.de"), or nil.
  # label: the domain without its public suffix ("paypal").
  def sensitive_category(domain, label)
    SENSITIVE_DOMAINS[domain] || SENSITIVE_BRANDS[label]
  end

  # The most severe of the given levels, or nil when none is a known level.
  def highest_level(levels)
    levels.select { |l| LEVELS.include?(l) }.min_by { |l| LEVELS.index(l) }
  end
end
