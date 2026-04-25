use std::env;

fn handle_request() -> String {
    let user_input = env::var("USER_INPUT").unwrap();
    let body = HttpResponse::Ok().body(user_input);
    body
}
