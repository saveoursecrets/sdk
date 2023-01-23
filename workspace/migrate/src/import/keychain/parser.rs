//! Parser for keychain access dumps.
use std::{collections::HashMap, ops::Range};

use logos::{Lexer, Logos};

use super::{Error, Result};

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

    /// Get a lex for the current source.
    fn lex(&self) -> Lexer<'s, Token> {
        Token::lexer(self.source)
    }

    /// Parse the keychain dump.
    pub fn parse(&self) -> Result<Vec<KeychainEntry<'s>>> {
        let mut result: Vec<KeychainEntry<'s>> = Vec::new();
        let mut lex = self.lex();
        let mut in_attributes = false;
        let mut next_token = lex.next();
        while let Some(token) = next_token {
            //println!("{:#?}", token);
            match token {
                Token::Keychain => {
                    in_attributes = false;
                    let advance_token = Self::consume_whitespace(&mut lex);
                    let range = Self::parse_quoted_string(
                        &mut lex,
                        self.source,
                        advance_token,
                    )?;
                    let entry = KeychainEntry {
                        keychain: &self.source[range],
                        version: None,
                        class: None,
                        attributes: HashMap::new(),
                    };
                    result.push(entry);
                }
                Token::Version => {
                    let token = Self::consume_whitespace(&mut lex);
                    let range =
                        Self::parse_number(&mut lex, self.source, token)?;
                    if let Some(last) = result.last_mut() {
                        last.version = Some(&self.source[range]);
                    }
                }
                Token::Class => {
                    let token = Self::consume_whitespace(&mut lex);
                    let range = Self::parse_quoted_string(
                        &mut lex,
                        self.source,
                        token,
                    )?;
                    if let Some(last) = result.last_mut() {
                        let class = &self.source[range];
                        last.class = Some(class.try_into()?);
                    }
                }
                Token::Attributes => {
                    in_attributes = true;
                    let token = Self::consume_whitespace(&mut lex);
                    next_token = token;
                    continue;
                }
                _ => {
                    if in_attributes {
                        let range = Self::parse_quoted_string(
                            &mut lex,
                            self.source,
                            Some(token),
                        )?;
                        let name = &self.source[range];
                        let name: AttributeName = name.try_into()?;
                        let token = Self::consume_whitespace(&mut lex);

                        let range = Self::parse_attribute_type(
                            &mut lex,
                            self.source,
                            token,
                        )?;
                        let attr_type = &self.source[range];
                        let attr_type: AttributeType =
                            attr_type.try_into()?;

                        // Consume the equls sign
                        let equals = lex.next();
                        if !matches!(equals, Some(Token::Equality)) {
                            return Err(Error::ParseExpectsEquals);
                        }

                        let value = Self::parse_attribute_value(
                            &mut lex,
                            self.source,
                            &attr_type,
                        )?;

                        if let Some(last) = result.last_mut() {
                            let key = AttributeKey(name, attr_type);
                            last.attributes.insert(key, value);
                        }

                        let token = Self::consume_whitespace(&mut lex);
                        next_token = token;
                        continue;
                    }
                }
            }

            next_token = lex.next();
        }
        Ok(result)
    }

    fn consume_whitespace(lex: &mut Lexer<Token>) -> Option<Token> {
        while let Some(token) = lex.next() {
            match token {
                Token::WhiteSpace => {}
                _ => return Some(token),
            }
        }
        None
    }

    fn parse_quoted_string(
        lex: &mut Lexer<Token>,
        source: &str,
        mut next_token: Option<Token>,
    ) -> Result<Range<usize>> {
        let mut in_quote = false;
        let mut begin: Range<usize> = lex.span();

        while let Some(token) = next_token {
            match token {
                Token::HexValue => {
                    return Ok(lex.span());
                }
                Token::DoubleQuote => {
                    if !in_quote {
                        begin = lex.span();
                        in_quote = true;
                    } else {
                        return Ok(begin.end..lex.span().start);
                    }
                }
                _ => {}
            }
            next_token = lex.next();
        }
        Err(Error::ParseNotQuoted((&source[lex.span()]).to_owned()))
    }

    fn parse_attribute_type(
        lex: &mut Lexer<Token>,
        source: &str,
        mut next_token: Option<Token>,
    ) -> Result<Range<usize>> {
        while let Some(token) = next_token {
            match token {
                Token::Type => return Ok(lex.span()),
                _ => {}
            }
            next_token = lex.next();
        }
        Err(Error::ParseNotAttributeType(
            (&source[lex.span()]).to_owned(),
        ))
    }

    fn parse_attribute_value<'a>(
        lex: &mut Lexer<Token>,
        source: &'a str,
        attr_type: &AttributeType,
    ) -> Result<AttributeValue<'a>> {
        match *attr_type {
            AttributeType::Blob => {
                while let Some(token) = lex.next() {
                    match token {
                        Token::Null => return Ok(AttributeValue::Null),
                        Token::HexValue => {
                            let hex_value = &source[lex.span()];
                            let token = Self::consume_whitespace(lex);
                            let range = Self::parse_quoted_string(
                                lex,
                                source,
                                token,
                            )?;
                            let value = &source[range];
                            return Ok(AttributeValue::HexBlob(hex_value, value));
                        }
                        Token::DoubleQuote => {
                            let range = Self::parse_quoted_string(
                                lex,
                                source,
                                Some(token),
                            )?;
                            let value = &source[range];
                            return Ok(AttributeValue::Blob(value));
                        }
                        _ => {}
                    }
                }
            }
            AttributeType::TimeDate => {
                while let Some(token) = lex.next() {
                    match token {
                        Token::Null => return Ok(AttributeValue::Null),
                        Token::HexValue => {
                            let token = Self::consume_whitespace(lex);
                            let range = Self::parse_quoted_string(
                                lex, source, token,
                            )?;
                            let value = &source[range];
                            return Ok(AttributeValue::TimeDate(value));
                        }
                        _ => {}
                    }
                }
            }
            AttributeType::Uint32 => {
                while let Some(token) = lex.next() {
                    match token {
                        Token::Null => return Ok(AttributeValue::Null),
                        Token::DoubleQuote => {
                            let range = Self::parse_quoted_string(
                                lex,
                                source,
                                Some(token),
                            )?;
                            let value = &source[range];
                            return Ok(AttributeValue::Uint32(value));
                        }
                        _ => {}
                    }
                }
            }
            AttributeType::Sint32 => {
                while let Some(token) = lex.next() {
                    match token {
                        Token::Null => return Ok(AttributeValue::Null),
                        Token::DoubleQuote => {
                            let range = Self::parse_quoted_string(
                                lex,
                                source,
                                Some(token),
                            )?;
                            let value = &source[range];
                            return Ok(AttributeValue::Sint32(value));
                        }
                        _ => {}
                    }
                }
            }
        }
        Err(Error::ParseNotAttributeValue(
            (&source[lex.span()]).to_owned(),
        ))
    }

    fn parse_number(
        lex: &mut Lexer<Token>,
        source: &str,
        mut next_token: Option<Token>,
    ) -> Result<Range<usize>> {
        while let Some(token) = next_token {
            match token {
                Token::Number => return Ok(lex.span()),
                _ => {}
            }
            next_token = lex.next();
        }
        Err(Error::ParseNotNumber((&source[lex.span()]).to_owned()))
    }
}

/// Represents the class of keychain entry.
#[derive(Debug)]
pub enum EntryClass {
    /// Generic password or note
    GenericPassword,
    /// Password stored by safari or other apps
    InternetPassword,
    /// Apple share password (deprecated)
    AppleSharePassword,
    /// Certificate
    Certificate,
    /// Public key
    PublicKey,
    /// Private key
    PrivateKey,
    /// Symmetric key
    SymmetricKey,
}

impl TryFrom<&str> for EntryClass {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self> {
        match value {
            "genp" => Ok(Self::GenericPassword),
            "inet" => Ok(Self::InternetPassword),
            "ashp" => Ok(Self::AppleSharePassword),
            "0x80001000" => Ok(Self::Certificate),
            "0x0000000F" => Ok(Self::PublicKey),
            "0x00000010" => Ok(Self::PrivateKey),
            "0x00000011" => Ok(Self::SymmetricKey),
            _ => Err(Error::ParseUnknownClass(value.to_owned())),
        }
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
    /// Unknown.
    SecProtItemAttr,
}

impl<'s> TryFrom<&'s str> for AttributeName<'s> {
    type Error = Error;

    fn try_from(value: &'s str) -> Result<Self> {
        match value {
            "cdat" => Ok(Self::SecCreationDateItemAttr),
            "mdat" => Ok(Self::SecModDateItemAttr),
            "desc" => Ok(Self::SecDescriptionItemAttr),
            "icmt" => Ok(Self::SecCommentItemAttr),
            "crtr" => Ok(Self::SecCreatorItemAttr),
            "type" => Ok(Self::SecTypeItemAttr),
            "scrp" => Ok(Self::SecScriptCodeItemAttr),
            "labl" => Ok(Self::SecLabelItemAttr),
            "invi" => Ok(Self::SecInvisibleItemAttr),
            "nega" => Ok(Self::SecNegativeItemAttr),
            "cusi" => Ok(Self::SecCustomIconItemAttr),
            "acct" => Ok(Self::SecAccountItemAttr),
            "svce" => Ok(Self::SecServiceItemAttr),
            "gena" => Ok(Self::SecGenericItemAttr),
            "sdmn" => Ok(Self::SecSecurityDomainItemAttr),
            "srvr" => Ok(Self::SecServerItemAttr),
            "atyp" => Ok(Self::SecAuthenticationTypeItemAttr),
            "port" => Ok(Self::SecPortItemAttr),
            "path" => Ok(Self::SecPathItemAttr),
            "vlme" => Ok(Self::SecVolumeItemAttr),
            "addr" => Ok(Self::SecAddressItemAttr),
            "ssig" => Ok(Self::SecSignatureItemAttr),
            "ptcl" => Ok(Self::SecProtocolItemAttr),
            "ctyp" => Ok(Self::SecCertificateType),
            "cenc" => Ok(Self::SecCertificateEncoding),
            "crtp" => Ok(Self::SecCrlType),
            "crnc" => Ok(Self::SecCrlEncoding),
            "alis" => Ok(Self::SecAlias),
            // ???
            "prot" => Ok(Self::SecProtItemAttr),
            _ => {
                if value.starts_with("0x") {
                    Ok(Self::Hex(value))
                } else {
                    Err(Error::ParseUnknownAttributeName(value.to_string()))
                }
            }
        }
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
        match value {
            "<blob>" => Ok(Self::Blob),
            "<uint32>" => Ok(Self::Uint32),
            "<sint32>" => Ok(Self::Sint32),
            "<timedate>" => Ok(Self::TimeDate),
            _ => Err(Error::ParseUnknownAttributeType(value.to_owned())),
        }
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
    /// Hex blob value.
    HexBlob(&'s str, &'s str),
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
