from helper import get_user_input, transform

data = get_user_input()

# Call with escape_html=False -> passthrough path, taint reaches eval
raw = transform(data, False)
eval(raw)
