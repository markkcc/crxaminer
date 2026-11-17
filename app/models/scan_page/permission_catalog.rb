module ScanPage
  # Plain-language descriptions and documentation links for Chrome's
  # documented extension permissions, and the rows of the Permissions table.
  # The rating column comes from the rule engine's own lists, so it always
  # agrees with the findings.
  class PermissionCatalog
    Row = Struct.new(:name, :description, :rating, :doc_url, keyword_init: true)

    DOCS_BASE = "https://developer.chrome.com/docs/extensions/reference/api/".freeze
    PERMISSIONS_LIST_URL = "https://developer.chrome.com/docs/extensions/reference/permissions-list".freeze

    # name => [what it allows, API page under DOCS_BASE or nil for the list page]
    ENTRIES = {
      "accessibilityFeatures.modify" => ["Change accessibility settings", "accessibilityFeatures"],
      "accessibilityFeatures.read" => ["Read accessibility settings", "accessibilityFeatures"],
      "activeTab" => ["Use the current tab, only after you click the extension or choose one of its menu items or shortcuts", nil],
      "alarms" => ["Schedule its own code to run at set times", "alarms"],
      "audio" => ["Read and control audio devices (ChromeOS)", "audio"],
      "background" => ["Keep running in the background after Chrome's windows are closed (legacy)", nil],
      "bookmarks" => ["Read and change your bookmarks", "bookmarks"],
      "browsingData" => ["Clear browsing data such as history, cookies and cache", "browsingData"],
      "certificateProvider" => ["Provide client certificates to ChromeOS", "certificateProvider"],
      "clipboardRead" => ["Read what you copy to the clipboard", nil],
      "clipboardWrite" => ["Write to the clipboard", nil],
      "contentSettings" => ["Change per-site settings such as JavaScript, cookies, camera and microphone", "contentSettings"],
      "contextMenus" => ["Add items to the right-click menu", "contextMenus"],
      "cookies" => ["Read and change cookies for the sites it has access to", "cookies"],
      "debugger" => ["Attach Chrome's debugger to tabs, which gives full control over those pages", "debugger"],
      "declarativeContent" => ["Show its button depending on page content, without reading the page", "declarativeContent"],
      "declarativeNetRequest" => ["Block or change network requests using rules it declares", "declarativeNetRequest"],
      "declarativeNetRequestFeedback" => ["See which of its request rules matched", "declarativeNetRequest"],
      "declarativeNetRequestWithHostAccess" => ["Block or change network requests with declared rules, on sites it has access to", "declarativeNetRequest"],
      "desktopCapture" => ["Capture the screen, a window or a tab, after you pick one", "desktopCapture"],
      "dns" => ["Look up host names", "dns"],
      "documentScan" => ["Use document scanners (ChromeOS)", "documentScan"],
      "downloads" => ["Start downloads and read and change your download history", "downloads"],
      "downloads.open" => ["Open downloaded files", "downloads"],
      "downloads.shelf" => ["Change the downloads bar (legacy)", "downloads"],
      "downloads.ui" => ["Change the downloads bubble", "downloads"],
      "enterprise.deviceAttributes" => ["Read device attributes on managed ChromeOS devices", "enterprise/deviceAttributes"],
      "enterprise.hardwarePlatform" => ["Read the hardware maker and model on managed devices", "enterprise/hardwarePlatform"],
      "enterprise.networkingAttributes" => ["Read network details on managed ChromeOS devices", "enterprise/networkingAttributes"],
      "enterprise.platformKeys" => ["Use enterprise certificates on managed ChromeOS devices", "enterprise/platformKeys"],
      "favicon" => ["Show the icons of websites", nil],
      "fileBrowserHandler" => ["Handle files in the ChromeOS Files app", "fileBrowserHandler"],
      "fileSystemProvider" => ["Provide file systems to the ChromeOS Files app", "fileSystemProvider"],
      "fontSettings" => ["Read and change Chrome's font settings", "fontSettings"],
      "gcm" => ["Receive push messages through Firebase Cloud Messaging", "gcm"],
      "geolocation" => ["Use your location without asking each time", nil],
      "history" => ["Read and change your browsing history", "history"],
      "identity" => ["Sign you in to services through OAuth", "identity"],
      "identity.email" => ["Read the email address of the signed-in Chrome profile", "identity"],
      "idle" => ["Detect when the computer is idle or locked", "idle"],
      "input" => ["Act as a keyboard or input method (ChromeOS)", "input/ime"],
      "loginState" => ["Read whether you are signed in (ChromeOS)", "loginState"],
      "management" => ["List, turn on or off, and uninstall your other extensions and apps", "management"],
      "nativeMessaging" => ["Exchange messages with programs installed on your computer", nil],
      "notifications" => ["Show system notifications", "notifications"],
      "offscreen" => ["Open hidden pages to use web APIs in the background", "offscreen"],
      "pageCapture" => ["Save pages as MHTML files", "pageCapture"],
      "platformKeys" => ["Use client certificates managed by ChromeOS", "platformKeys"],
      "power" => ["Keep the computer or display awake", "power"],
      "printerProvider" => ["Provide printers to Chrome's print dialog", "printerProvider"],
      "printing" => ["Send print jobs to printers (ChromeOS)", "printing"],
      "printingMetrics" => ["Read printing history on managed ChromeOS devices", "printingMetrics"],
      "privacy" => ["Change privacy-related browser settings", "privacy"],
      "processes" => ["Read information about Chrome's processes", "processes"],
      "proxy" => ["Choose the proxy server that your browser traffic goes through", "proxy"],
      "readingList" => ["Read and change your reading list", "readingList"],
      "scripting" => ["Run scripts and add styles in pages it has access to", "scripting"],
      "search" => ["Run searches with your default search engine", "search"],
      "sessions" => ["Read and restore recently closed tabs and windows, including from your other devices", "sessions"],
      "sidePanel" => ["Show its own page in Chrome's side panel", "sidePanel"],
      "storage" => ["Save data in the extension's own storage", "storage"],
      "system.cpu" => ["Read processor information", "system/cpu"],
      "system.display" => ["Read display information", "system/display"],
      "system.memory" => ["Read memory information", "system/memory"],
      "system.storage" => ["Read information about storage devices and eject removable ones", "system/storage"],
      "tabCapture" => ["Record the video and audio of a tab", "tabCapture"],
      "tabGroups" => ["Read and change tab groups", "tabGroups"],
      "tabs" => ["See the address and title of every open tab", "tabs"],
      "topSites" => ["Read your most visited sites", "topSites"],
      "tts" => ["Read text aloud with speech synthesis", "tts"],
      "ttsEngine" => ["Provide a text-to-speech voice", "ttsEngine"],
      "unlimitedStorage" => ["Store more data than the usual limit", nil],
      "userScripts" => ["Run user scripts that it manages in pages", "userScripts"],
      "vpnProvider" => ["Provide a VPN (ChromeOS)", "vpnProvider"],
      "wallpaper" => ["Change the wallpaper (ChromeOS)", "wallpaper"],
      "webAuthenticationProxy" => ["Answer Web Authentication requests on behalf of sites (remote desktop)", "webAuthenticationProxy"],
      "webNavigation" => ["See the address of each page as you navigate", "webNavigation"],
      "webRequest" => ["Watch network requests to the sites it has access to", "webRequest"],
      "webRequestAuthProvider" => ["Answer sign-in prompts for HTTP authentication", "webRequest"],
      "webRequestBlocking" => ["Block or change network requests while they happen", "webRequest"]
    }.freeze

    def self.description(name)
      ENTRIES.dig(name, 0)
    end

    def self.doc_url(name)
      return nil unless ENTRIES.key?(name)

      page = ENTRIES[name][1]
      page ? DOCS_BASE + page : PERMISSIONS_LIST_URL
    end

    # "High", "Medium" or nil, exactly as the rule engine rates the name.
    def self.rating(name)
      if ExtensionAnalyzerData::HIGH_RISK_PERMISSIONS.key?(name) then "High"
      elsif ExtensionAnalyzerData::MEDIUM_RISK_PERMISSIONS.key?(name) then "Medium"
      end
    end

    def self.row(entry)
      name = ScanPage.text(entry)
      known = entry.is_a?(String)
      Row.new(name: name, description: known ? description(entry) : nil,
              rating: known ? rating(entry) : nil, doc_url: known ? doc_url(entry) : nil)
    end

    def initialize(manifest)
      @manifest = manifest.is_a?(Hash) ? manifest : {}
    end

    # API permissions only. In Manifest V2 match patterns can sit in the same
    # list; SiteAccess shows those. Manifest V3 ignores patterns there, so they
    # stay in the table as unknown entries rather than disappear.
    def required
      @required ||= rows(:permissions)
    end

    def optional
      @optional ||= rows(:optional_permissions)
    end

    private

    def manifest_v2?
      ScanPage.value(@manifest, :manifest_version).to_i < 3
    end

    def rows(key)
      ScanPage.list(ScanPage.value(@manifest, key))
        .reject { |entry| entry.nil? || (manifest_v2? && SiteAccess.pattern?(entry)) }
        .uniq
        .map { |entry| self.class.row(entry) }
    end
  end
end
