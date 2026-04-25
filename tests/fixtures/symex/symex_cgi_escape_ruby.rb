# URL encoding at shell sink — wrong-type sanitizer (Ruby).
#
# CGI.escape in Ruby is percent-encoding (NOT HTML escape — that's
# CGI.escapeHTML).  It is registered as Sanitizer(HTML_ESCAPE) in the
# Ruby label rules (an existing approximation, out of scope here), so
# the HTML_ESCAPE bit is stripped but SHELL_ESCAPE remains and the
# taint engine still emits a finding when the encoded string flows
# into `system`.
#
# Symex should classify CGI.escape as TransformKind::UrlEncode (its
# true semantics) and produce a renderable witness whose concrete
# fold contains percent-escaped characters — confirming the new Ruby
# transform classifier is wired through to witness rendering.

require 'cgi'
require 'sinatra'

get '/run' do
  user_input = params[:cmd]
  escaped = CGI.escape(user_input)
  system("ls #{escaped}")
end
