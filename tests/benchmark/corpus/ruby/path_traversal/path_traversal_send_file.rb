def download(params)
  path = params[:path]
  send_file(path)
end
