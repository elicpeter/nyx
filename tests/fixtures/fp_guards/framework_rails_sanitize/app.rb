# FP GUARD — framework-safe pattern (Rails sanitize).
#
# The `sanitize` helper is an HTML_ESCAPE-equivalent sanitiser in
# Rails: it strips dangerous tags/attributes and returns a safe
# string.  Any tainted value flowing through sanitize before reaching
# `render` must not surface as taint-unsanitised-flow.
#
# Expected: NO taint-unsanitised-flow finding.

class CommentsController
  def show(params)
    user_html = params[:body]      # tainted
    safe_html = sanitize(user_html) # HTML_ESCAPE sanitiser
    render inline: safe_html
  end
end
