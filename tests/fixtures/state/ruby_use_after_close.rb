def use_after_close(path)
  f = File.open(path, 'r')
  f.close
  data = f.read
  data
end
