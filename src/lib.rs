//! # output-sanitize-rs
//!
//! Strip dangerous HTML/SQL/shell snippets from LLM output before they
//! reach a render path, a query, or a shell. Rust port of
//! [`@mukundakatta/llm-output-sanitizer`](https://www.npmjs.com/package/@mukundakatta/llm-output-sanitizer).
//!
//! ## Example
//!
//! ```
//! use output_sanitize_rs::sanitize;
//! let r = sanitize("Hello <script>steal()</script>", Default::default());
//! assert!(!r.safe);
//! assert!(!r.text.contains("<script"));
//! ```

#![deny(missing_docs)]

/// Output target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Sink {
    /// No additional escaping (default).
    #[default]
    Markdown,
    /// HTML-escape `<`, `>`, `&` after stripping.
    Html,
}

/// One detection that was rewritten.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// Category (`html`, `sql`, `shell`).
    pub kind: &'static str,
    /// The original matched substring.
    pub matched: String,
}

/// Result of one sanitize pass.
#[derive(Debug, Clone)]
pub struct SanitizeResult {
    /// True when no findings fired.
    pub safe: bool,
    /// Rewritten text.
    pub text: String,
    /// What was removed.
    pub findings: Vec<Finding>,
}

/// Run the sanitizer.
pub fn sanitize(text: &str, sink: Sink) -> SanitizeResult {
    let mut findings = Vec::new();
    let mut out = String::with_capacity(text.len());
    let lower = text.to_ascii_lowercase();
    let lower_bytes = lower.as_bytes();
    let original_bytes = text.as_bytes();

    let mut i = 0;
    while i < original_bytes.len() {
        // HTML: <script>, <iframe>, <object>, <embed>, <form>, <meta>, <link>
        let tags = ["script", "iframe", "object", "embed", "form", "meta", "link"];
        let mut matched = false;
        if original_bytes[i] == b'<' {
            for tag in tags {
                let open = format!("<{}", tag);
                let close = format!("</{}", tag);
                if lower[i..].starts_with(&open) || lower[i..].starts_with(&close) {
                    // Find the closing '>' for this tag.
                    if let Some(end_rel) = lower_bytes[i..].iter().position(|&c| c == b'>') {
                        let end = i + end_rel + 1;
                        findings.push(Finding {
                            kind: "html",
                            matched: text[i..end].to_string(),
                        });
                        out.push_str("[removed:html]");
                        i = end;
                        matched = true;
                        break;
                    }
                }
            }
        }
        if matched {
            continue;
        }

        // SQL: DROP/TRUNCATE/ALTER/DELETE FROM/INSERT INTO at word boundary
        let sql_kws: &[&str] = &["drop ", "truncate ", "alter ", "delete from ", "insert into "];
        let mut sql_matched = None;
        for kw in sql_kws {
            if lower[i..].starts_with(kw) && at_word_boundary(original_bytes, i) {
                sql_matched = Some(*kw);
                break;
            }
        }
        if let Some(kw) = sql_matched {
            // Take through end of word or end of input.
            let mut end = i + kw.len();
            while end < original_bytes.len() && !original_bytes[end].is_ascii_whitespace() {
                end += 1;
            }
            findings.push(Finding {
                kind: "sql",
                matched: text[i..end].to_string(),
            });
            out.push_str("[removed:sql]");
            i = end;
            continue;
        }

        // Shell: rm -rf, curl|sh, wget|sh, chmod 777, sudo
        let shell_signals: &[&str] = &["rm -rf", "chmod 777", "sudo ", "curl ", "wget "];
        let mut shell_match = None;
        for sig in shell_signals {
            if lower[i..].starts_with(sig) && at_word_boundary(original_bytes, i) {
                shell_match = Some(*sig);
                break;
            }
        }
        if let Some(sig) = shell_match {
            let mut end = i + sig.len();
            while end < original_bytes.len()
                && original_bytes[end] != b'\n'
                && original_bytes[end] != b';'
            {
                end += 1;
            }
            findings.push(Finding {
                kind: "shell",
                matched: text[i..end].to_string(),
            });
            out.push_str("[removed:shell]");
            i = end;
            continue;
        }

        // Default: copy one byte (UTF-8 safe — non-ASCII passes through one byte at a time
        // because none of our patterns include multi-byte chars).
        let c = text[i..].chars().next().unwrap();
        out.push(c);
        i += c.len_utf8();
    }

    if sink == Sink::Html {
        out = out
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;");
    }

    SanitizeResult {
        safe: findings.is_empty(),
        text: out,
        findings,
    }
}

fn at_word_boundary(bytes: &[u8], i: usize) -> bool {
    i == 0 || !bytes[i - 1].is_ascii_alphanumeric()
}
