require "test_helper"

class HelpControllerTest < ActionDispatch::IntegrationTest
  WRITE_UP = "https://astarte.security/docs/tools/crxaminer".freeze

  test "the help page explains the scan and the rules, and ends with the write-up link" do
    get help_path

    assert_response :success
    assert_select "title", text: /How it works/
    assert_select "h1", count: 1, text: "How CRXaminer works"
    assert_equal ["What a scan does", "The rule engine", "Reading the result"], css_select("article h2").map { |h| h.text.strip }
    assert_select "article ol li", count: 4

    links = css_select("article a")
    assert_equal WRITE_UP, links.last["href"], "the write-up link comes last"
    assert_equal "_blank", links.last["target"]
    assert_includes links.last["rel"].to_s, "noopener"
  end

  test "the help link in the navigation opens the help page and is marked current there" do
    get root_path
    assert_select "header nav a[href='#{help_path}']", count: 1, text: "[ help ]"
    assert_select "header nav a[href='#{help_path}'][target]", count: 0, message: "it is a page of this site, opened in the same tab"
    assert_select "header nav a[href='#{WRITE_UP}']", count: 0

    get help_path
    assert_select "header nav a[aria-current=page]", count: 1, text: "[ help ]"
    assert_select "header a[href='/'] svg[aria-label=CRXaminer]", count: 1
    assert_select "footer a", count: 2
  end
end
