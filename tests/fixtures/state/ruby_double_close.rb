def double_close(path)
  f = File.open(path, 'r')
  f.close
  f.close
end
