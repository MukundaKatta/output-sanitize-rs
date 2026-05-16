# output-sanitize-rs

[![crates.io](https://img.shields.io/crates/v/output-sanitize-rs.svg)](https://crates.io/crates/output-sanitize-rs)

Strip dangerous HTML/SQL/shell snippets from LLM output before render,
query, or shell sinks. Rust port of
[`@mukundakatta/llm-output-sanitizer`](https://www.npmjs.com/package/@mukundakatta/llm-output-sanitizer).

```rust
use output_sanitize_rs::{sanitize, Sink};
let r = sanitize("Hello <script>steal()</script>", Sink::default());
```

Zero deps. MIT or Apache-2.0.
