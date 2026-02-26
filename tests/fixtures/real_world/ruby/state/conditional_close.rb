def maybe_close(path, flag)
  f = File.open(path, 'r')
  if flag
    data = f.read
    f.close
    data
  else
    "skipped"
  end
end
