def load_data(params)
  data = params[:data]
  obj = Marshal.load(data)
  obj.to_s
end
