mod content {
    pub struct RawHtml<T>(pub T);
}

struct Json<T>(T);

#[post("/hello", data = "<body>")]
fn hello(body: Json<String>) -> content::RawHtml<Json<String>> {
    content::RawHtml(body)
}
