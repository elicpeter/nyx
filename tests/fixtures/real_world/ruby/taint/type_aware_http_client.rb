require 'net/http'

def vulnerable_typed_request(params)
  host = params[:host]
  client = Net::HTTP.new(host, 443)
  client.request(Net::HTTP::Get.new("/"))
end
