use axum::{extract::Path, response::Html, routing::get, Router};

async fn greet(Path(name): Path<String>) -> Html<String> {
    Html(format!("<h1>Hello, {}!</h1>", name))
}

#[tokio::main]
async fn main() {
    let app: Router = Router::new().route("/hello/:name", get(greet));
    let _ = app;
}
