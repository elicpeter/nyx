use tree_sitter::Parser;

fn main() {
    let src: &[u8] = br#"@issues = Issue.where(:id => params[:id]).preload(:author).to_a
@x = User.where(id: 1).order(:created_at).pluck(:id, :name)
"#;
    let mut p = Parser::new();
    p.set_language(&tree_sitter_ruby::LANGUAGE.into()).unwrap();
    let t = p.parse(src, None).unwrap();
    print_tree(t.root_node(), src, 0);
}
fn print_tree(n: tree_sitter::Node, src: &[u8], depth: usize) {
    let indent = "  ".repeat(depth);
    let text: String = if n.child_count() == 0 {
        let s = std::str::from_utf8(&src[n.start_byte()..n.end_byte()]).unwrap_or("?");
        format!(" \"{}\"", s)
    } else {
        String::new()
    };
    println!("{}{}{}", indent, n.kind(), text);
    let mut c = n.walk();
    for ch in n.children(&mut c) {
        print_tree(ch, src, depth + 1);
    }
}
