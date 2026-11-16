require "socket"
require "json"

# A minimal HTTP server on 127.0.0.1 that answers each request with the next
# canned [status, body] pair and records what it received. Used to run the
# real Anthropic::Client end to end without any outbound network.
class StubMessagesServer
  Request = Struct.new(:request_line, :headers, :body, keyword_init: true) do
    def json
      JSON.parse(body)
    end
  end

  attr_reader :requests

  def initialize(*responses)
    @responses = responses
    @requests = []
    @server = TCPServer.new("127.0.0.1", 0)
    @thread = Thread.new { serve }
  end

  def base_url
    "http://127.0.0.1:#{@server.addr[1]}"
  end

  def close
    @server.close unless @server.closed?
    @thread.kill
  end

  private

  def serve
    loop do
      socket = @server.accept
      handle(socket)
    end
  rescue IOError, Errno::EBADF
    nil
  end

  def handle(socket)
    request_line = socket.gets.to_s
    headers = {}
    while (line = socket.gets) && line != "\r\n"
      name, value = line.split(":", 2)
      headers[name.strip.downcase] = value.to_s.strip
    end
    body = socket.read(headers["content-length"].to_i).to_s
    @requests << Request.new(request_line: request_line.strip, headers: headers, body: body)

    status, payload = @responses.shift || [500, { type: "error", error: { type: "api_error", message: "no canned response" } }]
    text = payload.is_a?(String) ? payload : JSON.generate(payload)
    socket.write("HTTP/1.1 #{status} #{status == 200 ? 'OK' : 'Error'}\r\n" \
                 "Content-Type: application/json\r\n" \
                 "Content-Length: #{text.bytesize}\r\n" \
                 "Connection: close\r\n\r\n#{text}")
  ensure
    socket&.close
  end
end
