def block_auto_close(path)
  File.open(path, 'r') { |f| f.read }
end

def manual_close(path)
  f = File.open(path, 'r')
  data = f.read
  f.close
  data
end

def forgot_close(path)
  f = File.open(path, 'r')
  f.read
end
