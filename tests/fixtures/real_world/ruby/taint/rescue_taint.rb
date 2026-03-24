def handle_request
  input = gets
  begin
    system(input)
  rescue => e
    puts e.message
  end
end
