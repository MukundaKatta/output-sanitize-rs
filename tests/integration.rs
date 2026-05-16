use output_sanitize_rs::{sanitize, Sink};

#[test]
fn strips_script_tag() {
    let r = sanitize("hello <script>alert(1)</script> world", Sink::default());
    assert!(!r.safe);
    assert!(!r.text.contains("<script"));
    assert!(r.findings.iter().any(|f| f.kind == "html"));
}

#[test]
fn strips_drop_table() {
    let r = sanitize("Sure: DROP TABLE users", Sink::default());
    assert!(!r.safe);
    assert!(r.findings.iter().any(|f| f.kind == "sql"));
    assert!(!r.text.contains("DROP"));
}

#[test]
fn strips_rm_rf() {
    let r = sanitize("run rm -rf / right now", Sink::default());
    assert!(!r.safe);
    assert!(r.findings.iter().any(|f| f.kind == "shell"));
}

#[test]
fn clean_text_passes_through() {
    let r = sanitize("a normal sentence", Sink::default());
    assert!(r.safe);
    assert_eq!(r.text, "a normal sentence");
}

#[test]
fn html_sink_escapes_remaining() {
    let r = sanitize("a < b & c", Sink::Html);
    assert!(r.text.contains("&lt;"));
    assert!(r.text.contains("&amp;"));
}
