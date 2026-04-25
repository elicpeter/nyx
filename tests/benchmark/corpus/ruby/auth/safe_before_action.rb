# ruby-before-action-001: Rails `before_action :authenticate_user`
# decorator gates the controller method.  Auth analysis must recognise
# the decorator as an authentication guard so neither `cfg-auth-gap` nor
# `state-unauthed-access` fires on the privileged FILE_IO sink.
class DownloadController < ApplicationController
  before_action :authenticate_user

  def handle_download(params)
    name = params[:file]
    if name.include?('..') || name.start_with?('/') || name.start_with?('\\')
      return 'denied'
    end
    File.read('/var/data/' + name)
  end
end
