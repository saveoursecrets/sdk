//! Parser for keychain access dumps.
use std::{collections::HashMap, ops::Range};

use logos::{Lexer, Logos};

use crate::{Error, Result};

#[derive(Logos, Debug, PartialEq)]
enum Token {
    #[token("keychain:")]
    Keychain,
    #[token("version:")]
    Version,
    #[token("class:")]
    Class,
    #[token("attributes:")]
    Attributes,
    #[token("=")]
    Equality,
    #[token("\"")]
    DoubleQuote,
    #[regex("(?i:0x[a-f0-9]+)")]
    HexValue,
    #[regex("\\d+")]
    Number,
    #[token("<NULL>")]
    Null,
    #[regex("<(blob|timedate|uint32|sint32)>")]
    Type,
    #[error]
    #[regex("[[:blank:]]", priority = 2)]
    WhiteSpace,
}

/// Parsed information from a keychain dump.
pub struct KeychainParser<'s> {
    source: &'s str,
}

impl<'s> KeychainParser<'s> {
    /// Create a new parser.
    pub fn new(source: &'s str) -> Self {
        Self { source }
    }

    /// Get a lexer for the current source.
    fn lexer(&self) -> Lexer<'s, Token> {
        Token::lexer(self.source)
    }

    /// Parse the keychain dump.
    pub fn parse(&self) -> Result<Vec<KeychainEntry<'s>>> {
        let mut result: Vec<KeychainEntry<'s>> = Vec::new();
        let mut lex = self.lexer();
        let mut in_attributes = false;
        let mut next_token = lex.next();
        while let Some(token) = next_token {
            //println!("{:#?}", token);
            match token {
                Token::Keychain => {
                    in_attributes = false;
                    let advance_token = consume_whitespace(&mut lex);
                    let range = parse_quoted_string(&mut lex, advance_token)?;
                    let entry = KeychainEntry {
                        keychain: &self.source[range],
                        version: None,
                        class: None,
                        attributes: HashMap::new(),
                    };
                    result.push(entry);
                }
                Token::Version => {
                    let token = consume_whitespace(&mut lex);
                    let range = parse_number(&mut lex, token)?;
                    if let Some(last) = result.last_mut() {
                        last.version = Some(&self.source[range]);
                    }
                }
                Token::Class => {
                    let token = consume_whitespace(&mut lex);
                    let range = parse_quoted_string(&mut lex, token)?;
                    if let Some(last) = result.last_mut() {
                        let class = &self.source[range];
                        last.class = Some(class.try_into()?);
                    }
                }
                Token::Attributes => {
                    in_attributes = true;
                    let token = consume_whitespace(&mut lex);
                    next_token = token;
                    continue;
                }
                _ => {
                    if in_attributes {
                        let range =
                            parse_quoted_string(&mut lex, Some(token))?;
                        let name = &self.source[range];
                        let name: AttributeName = name.try_into()?;
                        let token = consume_whitespace(&mut lex);

                        let range = parse_attribute_type(&mut lex, token)?;
                        let attr_type = &self.source[range];
                        let attr_type: AttributeType =
                            attr_type.try_into()?;

                        // Consume the equls sign
                        let equals = lex.next();
                        if !matches!(equals, Some(Token::Equality)) {
                            panic!("expecting equals sign");
                        }

                        let value = parse_attribute_value(
                            &mut lex,
                            self.source,
                            &attr_type,
                        )?;

                        if let Some(last) = result.last_mut() {
                            let key = AttributeKey(name, attr_type);
                            last.attributes.insert(key, value);
                        }

                        let token = consume_whitespace(&mut lex);
                        next_token = token;
                        continue;
                    }
                }
            }

            next_token = lex.next();
        }
        Ok(result)
    }
}

/// Represents the class of keychain entry.
#[derive(Debug)]
pub enum EntryClass {
    /// Generic password or note.
    GenericPassword,
    /// Password stored by safari or other apps.
    InternetPassword,
    /// Apple share password (deprecated)
    AppleSharePassword,
    /*
    kSecCertificateItemClass        = 0x80001000,
    kSecPublicKeyItemClass          = 0x0000000F,
    kSecPrivateKeyItemClass         = 0x00000010,
    kSecSymmetricKeyItemClass       = 0x00000011
    */
}

impl TryFrom<&str> for EntryClass {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self> {
        Ok(match value {
            "genp" => Self::GenericPassword,
            "inet" => Self::InternetPassword,
            "ashp" => Self::AppleSharePassword,
            _ => panic!("unknown keychain item class"),
        })
    }
}

/// The name of an attribute.
#[derive(Debug, Eq, PartialEq, Hash)]
pub enum AttributeName<'s> {
    // SEE: https://gist.github.com/santigz/601f4fd2f039d6ceb2198e2f9f4f01e0
    /// Hex value.
    Hex(&'s str),
    /// Creation date.
    SecCreationDateItemAttr,
    /// Modification date.
    SecModDateItemAttr,
    /// Description of the item.
    SecDescriptionItemAttr,
    /// Comment of the item.
    SecCommentItemAttr,
    /// Creator of the item.
    SecCreatorItemAttr,
    /// Type of the item.
    SecTypeItemAttr,
    /// Script code for the item.
    SecScriptCodeItemAttr,
    /// Label of the item.
    SecLabelItemAttr,
    /// Invisiblility.
    SecInvisibleItemAttr,
    /// Negative item.
    SecNegativeItemAttr,
    /// Custom icon.
    SecCustomIconItemAttr,
    /// Account name.
    SecAccountItemAttr,
    /// Service name.
    SecServiceItemAttr,
    /// Generic item.
    SecGenericItemAttr,
    /// Security domain.
    SecSecurityDomainItemAttr,
    /// Server item.
    SecServerItemAttr,
    /// Authentication type.
    SecAuthenticationTypeItemAttr,
    /// Port.
    SecPortItemAttr,
    /// Path.
    SecPathItemAttr,
    /// Volume.
    SecVolumeItemAttr,
    /// Address.
    SecAddressItemAttr,
    /// Signature.
    SecSignatureItemAttr,
    /// Protocol.
    SecProtocolItemAttr,
    /// Certificate.
    SecCertificateType,
    /// Certificate encoding.
    SecCertificateEncoding,
    /// Unknown.
    SecCrlType,
    /// Unknown.
    SecCrlEncoding,
    /// Unknown.
    SecAlias,

    // ???
    /// Unknown.
    SecProtItemAttr,
}

impl<'s> TryFrom<&'s str> for AttributeName<'s> {
    type Error = Error;

    fn try_from(value: &'s str) -> Result<Self> {
        Ok(match value {
            "cdat" => Self::SecCreationDateItemAttr,
            "mdat" => Self::SecModDateItemAttr,
            "desc" => Self::SecDescriptionItemAttr,
            "icmt" => Self::SecCommentItemAttr,
            "crtr" => Self::SecCreatorItemAttr,
            "type" => Self::SecTypeItemAttr,
            "scrp" => Self::SecScriptCodeItemAttr,
            "labl" => Self::SecLabelItemAttr,
            "invi" => Self::SecInvisibleItemAttr,
            "nega" => Self::SecNegativeItemAttr,
            "cusi" => Self::SecCustomIconItemAttr,
            "acct" => Self::SecAccountItemAttr,
            "svce" => Self::SecServiceItemAttr,
            "gena" => Self::SecGenericItemAttr,
            "sdmn" => Self::SecSecurityDomainItemAttr,
            "srvr" => Self::SecServerItemAttr,
            "atyp" => Self::SecAuthenticationTypeItemAttr,
            "port" => Self::SecPortItemAttr,
            "path" => Self::SecPathItemAttr,
            "vlme" => Self::SecVolumeItemAttr,
            "addr" => Self::SecAddressItemAttr,
            "ssig" => Self::SecSignatureItemAttr,
            "ptcl" => Self::SecProtocolItemAttr,
            "ctyp" => Self::SecCertificateType,
            "cenc" => Self::SecCertificateEncoding,
            "crtp" => Self::SecCrlType,
            "crnc" => Self::SecCrlEncoding,
            "alis" => Self::SecAlias,

            // ???
            "prot" => Self::SecProtItemAttr,
            _ => {
                if value.starts_with("0x") {
                    Self::Hex(value)
                } else {
                    panic!(
                        "{}",
                        &format!("unknown keychain attribute name {}", value)
                    );
                }
            }
        })
    }
}

/// Enumeration of attribute types.
#[derive(Debug, Eq, PartialEq, Hash)]
pub enum AttributeType {
    /// Blob attribute type.
    Blob,
    /// Uint32 attribute type.
    Uint32,
    /// Sint32 attribute type.
    Sint32,
    /// TimeDate attribute type.
    TimeDate,
}

impl TryFrom<&str> for AttributeType {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self> {
        Ok(match value {
            "<blob>" => Self::Blob,
            "<uint32>" => Self::Uint32,
            "<sint32>" => Self::Sint32,
            "<timedate>" => Self::TimeDate,
            _ => {
                panic!(
                    "{}",
                    &format!("unknown keychain attribute type {}", value)
                );
            }
        })
    }
}

/// Key for an attribute.
#[derive(Debug, Eq, PartialEq, Hash)]
pub struct AttributeKey<'s>(pub AttributeName<'s>, pub AttributeType);

/// Value of an attribute.
#[derive(Debug, Eq, PartialEq, Hash)]
pub enum AttributeValue<'s> {
    /// Null value.
    Null,
    /// Time date value.
    TimeDate(&'s str),
    /// Blob value.
    Blob(&'s str),
    /// Uint32 value.
    Uint32(&'s str),
    /// Sint32 value.
    Sint32(&'s str),
}

/// Entry in a keychain dump.
#[derive(Debug)]
pub struct KeychainEntry<'s> {
    /// The keychain path.
    keychain: &'s str,
    /// Keychain version.
    version: Option<&'s str>,
    /// Item class.
    class: Option<EntryClass>,
    /// Attributes mapping.
    attributes: HashMap<AttributeKey<'s>, AttributeValue<'s>>,
}

fn consume_whitespace(lexer: &mut Lexer<Token>) -> Option<Token> {
    while let Some(token) = lexer.next() {
        match token {
            Token::WhiteSpace => {}
            _ => return Some(token),
        }
    }
    None
}

fn parse_quoted_string(
    lexer: &mut Lexer<Token>,
    mut next_token: Option<Token>,
) -> Result<Range<usize>> {
    let mut in_quote = false;
    let mut begin: Range<usize> = lexer.span();

    while let Some(token) = next_token {
        match token {
            Token::HexValue => {
                return Ok(lexer.span());
            }
            Token::DoubleQuote => {
                if !in_quote {
                    begin = lexer.span();
                    in_quote = true;
                } else {
                    return Ok(begin.end..lexer.span().start);
                }
            }
            _ => {}
        }
        next_token = lexer.next();
    }
    panic!("not a quoted string")
}

fn parse_attribute_type(
    lexer: &mut Lexer<Token>,
    mut next_token: Option<Token>,
) -> Result<Range<usize>> {
    while let Some(token) = next_token {
        match token {
            Token::Type => return Ok(lexer.span()),
            _ => {}
        }
        next_token = lexer.next();
    }
    panic!("not an attribute type")
}

fn parse_attribute_value<'a>(
    lexer: &mut Lexer<Token>,
    source: &'a str,
    attr_type: &AttributeType,
) -> Result<AttributeValue<'a>> {
    match *attr_type {
        AttributeType::Blob => {
            while let Some(token) = lexer.next() {
                match token {
                    Token::Null => return Ok(AttributeValue::Null),
                    _ => {
                        let range = parse_quoted_string(lexer, Some(token))?;
                        let value = &source[range];
                        return Ok(AttributeValue::Blob(value));
                    }
                }
            }
        }
        AttributeType::TimeDate => {
            while let Some(token) = lexer.next() {
                match token {
                    Token::Null => return Ok(AttributeValue::Null),
                    Token::HexValue => {
                        let token = consume_whitespace(lexer);
                        let range = parse_quoted_string(lexer, token)?;
                        let value = &source[range];
                        return Ok(AttributeValue::TimeDate(value));
                    }
                    _ => {}
                }
            }
        }
        AttributeType::Uint32 => {
            while let Some(token) = lexer.next() {
                match token {
                    Token::Null => return Ok(AttributeValue::Null),
                    Token::DoubleQuote => {
                        let range = parse_quoted_string(lexer, Some(token))?;
                        let value = &source[range];
                        return Ok(AttributeValue::Uint32(value));
                    }
                    _ => {}
                }
            }
        }
        AttributeType::Sint32 => {
            while let Some(token) = lexer.next() {
                match token {
                    Token::Null => return Ok(AttributeValue::Null),
                    Token::DoubleQuote => {
                        let range = parse_quoted_string(lexer, Some(token))?;
                        let value = &source[range];
                        return Ok(AttributeValue::Sint32(value));
                    }
                    _ => {}
                }
            }
        }
    }

    panic!("not an attribute value")
}

fn parse_number(
    lexer: &mut Lexer<Token>,
    mut next_token: Option<Token>,
) -> Result<Range<usize>> {
    while let Some(token) = next_token {
        match token {
            Token::Number => return Ok(lexer.span()),
            _ => {}
        }
        next_token = lexer.next();
    }
    panic!("not a number")
}
