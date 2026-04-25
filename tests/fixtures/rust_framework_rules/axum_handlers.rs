use axum::extract::Path;
use axum::response::{Html, Redirect};

async fn show_profile(Path(name): Path<String>) -> Html<String> {
    Html(name)
}

async fn bounce(Path(next): Path<String>) -> Redirect {
    Redirect::to(&next)
}
