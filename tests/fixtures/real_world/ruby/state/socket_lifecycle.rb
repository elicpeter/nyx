require 'socket'

def connect_leak(host, port)
  s = TCPSocket.new(host, port)
  s.puts('hello')
  data = s.gets
  data
end

def connect_safe(host, port)
  s = TCPSocket.new(host, port)
  begin
    s.puts('hello')
    s.gets
  ensure
    s.close
  end
end
