use std::collections::{HashMap, HashSet};

struct Ctx;
struct Req;
struct User {
    id: i64,
}

mod auth {
    pub async fn require_auth(_r: &super::Req, _c: &super::Ctx) -> Result<super::User, ()> {
        Ok(super::User { id: 1 })
    }
}

pub async fn handle_list_peer_docs(req: Req, ctx: Ctx) -> Result<String, ()> {
    let user = auth::require_auth(&req, &ctx).await?;
    let doc_ids: Vec<i64> = vec![1, 2, 3];

    // Pure in-memory bookkeeping, no authorization decision here.
    let mut counts: HashMap<i64, usize> = HashMap::new();
    let mut seen: HashSet<i64> = HashSet::new();
    for doc_id in &doc_ids {
        counts.insert(*doc_id, 0);
        seen.insert(*doc_id);
        if seen.contains(doc_id) {
            counts.get(doc_id);
        }
    }
    let _ = user;
    Ok(format!("{} {}", counts.len(), seen.len()))
}
