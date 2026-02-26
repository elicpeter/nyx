def process_file(path)
  f = File.open(path, 'r')
  begin
    data = f.read
    return data
  rescue IOError => e
    puts e.message
  ensure
    f.close
  end
end

def leaky_process(path)
  f = File.open(path, 'r')
  data = f.read
  if data.empty?
    return nil  # f leaked
  end
  f.close
  data
end
