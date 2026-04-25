use actix_web::{HttpResponse, web};

async fn render_widget(payload: web::Json<String>) -> HttpResponse {
    HttpResponse::Ok().body(payload)
}
