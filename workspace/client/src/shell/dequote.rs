//! Parser so that the shell can accept quoted strings for arguments.
use core::ops::Range;
use logos::Logos;

#[derive(Logos, Debug, PartialEq)]
enum Token {
    // Tokens can be literal strings, of any length.
    #[token(r#"""#)]
    DoubleQuote,

    #[token("'")]
    SingleQuote,

    #[regex(r"[ \t\n\f]+")]
    WhiteSpace,

    #[error]
    Error,
}

enum QuoteType {
    Single,
    Double,
}

pub fn group(src: &str) -> Vec<String> {
    let mut lex = Token::lexer(src);
    let mut quote: Option<QuoteType> = None;

    let mut slices: Vec<Vec<Range<usize>>> = Vec::new();
    let mut current: Vec<Range<usize>> = vec![0..0];

    while let Some(token) = lex.next() {
        let span = lex.span();
        match token {
            Token::DoubleQuote => {
                if let Some(quote_type) = &quote {
                    // Close double quotes
                    if let QuoteType::Double = quote_type {
                        quote = None;
                        current.push(span.end..span.end);
                    }
                } else {
                    // Open double quotes
                    quote = Some(QuoteType::Double);
                    current.last_mut().unwrap().start = span.end;
                }
            }
            Token::SingleQuote => {
                if let Some(quote_type) = &quote {
                    // Close single quotes
                    if let QuoteType::Single = quote_type {
                        quote = None;
                        current.push(span.end..span.end);
                    }
                } else {
                    // Open single quotes
                    quote = Some(QuoteType::Single);
                    current.last_mut().unwrap().start = span.end;
                }
            }
            Token::WhiteSpace => {
                if quote.is_none() {
                    current.last_mut().unwrap().end = span.start;
                    slices.push(current);
                    current = vec![span.end..span.end];
                } else {
                    current.last_mut().unwrap().end = span.end;
                }
            }
            Token::Error => {
                current.last_mut().unwrap().end = span.end;
            }
        }
    }

    if current.last().unwrap().end == current.last().unwrap().start {
        current.pop();
    }

    slices.push(current);

    slices
        .iter()
        .map(|parts| {
            let mut value = String::new();
            for range in parts {
                if range.end > range.start {
                    value.push_str(&src[range.start..range.end]);
                }
            }
            value
        })
        .collect::<Vec<_>>()
}

#[cfg(test)]
mod test {
    use super::parse;

    #[test]
    fn args_parse() {
        // Single argument not quoted
        let args = "foo";
        let parsed = parse(args);
        assert_eq!(&["foo"], parsed.as_slice());

        // No quoted arguments
        let args = "a b c";
        let parsed = parse(args);
        assert_eq!(&["a", "b", "c"], parsed.as_slice());

        // Quoted single argument (double)
        let args = r#""a""#;
        let parsed = parse(args);
        assert_eq!(&["a"], parsed.as_slice());

        // Quoted single argument (single)
        let args = "'a'";
        let parsed = parse(args);
        assert_eq!(&["a"], parsed.as_slice());

        // Interspersed double quoted arguments
        let args = r#"a "b" c"#;
        let parsed = parse(args);
        assert_eq!(&["a", "b", "c"], parsed.as_slice());

        // Interspersed single quoted arguments
        let args = r#"a 'b' c"#;
        let parsed = parse(args);
        assert_eq!(&["a", "b", "c"], parsed.as_slice());

        // Mixed quote types
        let args = r#"a "b" 'c'"#;
        let parsed = parse(args);
        assert_eq!(&["a", "b", "c"], parsed.as_slice());

        // Double quoted whitespace
        let args = r#"a "b c" d"#;
        let parsed = parse(args);
        assert_eq!(&["a", "b c", "d"], parsed.as_slice());

        // Single quoted whitespace
        let args = r#"a 'b c' d"#;
        let parsed = parse(args);
        assert_eq!(&["a", "b c", "d"], parsed.as_slice());

        // Quoted with trailing value
        let args = r#"a "b c"d"#;
        let parsed = parse(args);
        assert_eq!(&["a", "b cd"], parsed.as_slice());

        // Quoted with trailing value and extra arg
        let args = r#"a "b c"d e"#;
        let parsed = parse(args);
        assert_eq!(&["a", "b cd", "e"], parsed.as_slice());

        //println!("{:#?}", parsed);
    }
}
