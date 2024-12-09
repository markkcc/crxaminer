module ApplicationHelper
    def rouge_highlight(code, language = 'json')
        formatter = Rouge::Formatters::HTML.new
        lexer = Rouge::Lexer.find(language) || Rouge::Lexers::PlainText.new
        formatter.format(lexer.lex(code))
      rescue StandardError => e
        Rails.logger.error "Rouge highlighting failed: #{e.message}"
        CGI.escape_html(code)  # Fallback to escaped plain text
    end
end
