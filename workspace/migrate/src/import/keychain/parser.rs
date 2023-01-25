//! Parser for keychain access dumps.
use std::{borrow::Cow, collections::HashMap, ops::Range};

use logos::{Lexer, Logos};

use super::{Error, Result};

/// The value for the type of generic passwords
/// that are of the note type.
const NOTE_TYPE: &str = "note";

/// The key in the plist dictionary that contains the
/// value of a secure note.
const NOTE_PLIST_KEY: &str = "NOTE";

#[derive(Logos, Debug, PartialEq)]
enum OctalToken {
    #[regex("\\\\(\\d\\d\\d)")]
    OctalEscape,
    #[error]
    Error,
}

/// Replace escaped octal sequences such as `\012` in a string.
pub fn unescape_octal(value: &str) -> Result<Cow<'_, str>> {
    let mut lex = OctalToken::lexer(value);
    let mut has_escape = false;
    let mut tokens = Vec::new();
    while let Some(token) = lex.next() {
        if let OctalToken::OctalEscape = token {
            has_escape = true;
        }
        let span = lex.span();
        tokens.push((token, span));
    }

    if !has_escape {
        Ok(Cow::Borrowed(value))
    } else {
        let mut s = String::new();
        for (token, span) in tokens {
            if let OctalToken::OctalEscape = token {
                let octal = &value[span.start + 1..span.end];
                let num = u32::from_str_radix(octal, 8)?;
                s.push(char::from_u32(num).ok_or(
                    Error::InvalidOctalEscape(
                        value[span.start..span.end].to_owned(),
                    ),
                )?);
            } else {
                s.push_str(&value[span]);
            }
        }
        Ok(Cow::Owned(s))
    }
}

/// Parse a plist and extract the value for a secure note.
pub fn plist_secure_note(
    value: &str,
    unescape: bool,
) -> Result<Option<Cow<str>>> {
    let plist = if unescape {
        unescape_octal(value)?
    } else {
        Cow::Borrowed(value)
    };
    let value: plist::Value = plist::from_bytes(plist.as_bytes())?;
    if let plist::Value::Dictionary(map) = value {
        if let Some(value) = map.get(NOTE_PLIST_KEY) {
            if let plist::Value::String(data) = value {
                return Ok(Some(Cow::Owned(data.to_owned())));
            }
        }
    }
    return Ok(None);
}

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
    #[token("data:")]
    Data,
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
    #[regex(r"[ \t\r\n\f]+")]
    WhiteSpace,
}

/// Parse the dump for a keychain.
///
/// Octal sequences are not handled, you should call
/// `unescape_octal()` when you need to replace octal
/// escape sequences.
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
    pub fn parse(&self) -> Result<KeychainList<'s>> {
        let mut entries: Vec<KeychainEntry<'s>> = Vec::new();
        let mut lex = self.lex();
        let mut in_attributes = false;
        let mut next_token = lex.next();
        while let Some(token) = next_token {
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
                        data: None,
                        attributes: HashMap::new(),
                    };
                    entries.push(entry);
                }
                Token::Version => {
                    let token = Self::consume_whitespace(&mut lex);
                    let range =
                        Self::parse_number(&mut lex, self.source, token)?;
                    if let Some(last) = entries.last_mut() {
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
                    if let Some(last) = entries.last_mut() {
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
                Token::Data => {
                    in_attributes = false;
                    let token = Self::consume_whitespace(&mut lex);
                    let value =
                        Self::parse_value(&mut lex, self.source, token)?;
                    if let Some(last) = entries.last_mut() {
                        last.data = Some(value);
                    }
                }
                _ => {
                    if in_attributes {
                        let range = Self::parse_attribute_name(
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

                        // Consume the equals sign
                        let equals = lex.next();
                        if !matches!(equals, Some(Token::Equality)) {
                            return Err(Error::ParseExpectsEquals);
                        }

                        let value = Self::parse_attribute_value(
                            &mut lex,
                            self.source,
                            &attr_type,
                        )?;

                        if let Some(last) = entries.last_mut() {
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
        Ok(KeychainList { entries })
    }

    fn consume_whitespace(lex: &mut Lexer<Token>) -> Option<Token> {
        lex.by_ref().find(|t| !matches!(t, Token::WhiteSpace))
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
                    if !in_quote {
                        return Ok(lex.span());
                    }
                }
                Token::DoubleQuote => {
                    if !in_quote {
                        begin = lex.span();
                        in_quote = true;
                    } else {
                        // We must check for EOF or newline to allow
                        // for nested quotes in the case of plist XML files
                        // used as values for secure notes
                        let finished = lex.remainder().len() == 0
                            || &lex.remainder()[0..1] == "\n";
                        if finished {
                            return Ok(begin.end..lex.span().start);
                        }
                    }
                }
                _ => {}
            }
            next_token = lex.next();
        }
        Err(Error::ParseNotQuoted(source[lex.span()].to_owned()))
    }

    fn parse_attribute_name(
        lex: &mut Lexer<Token>,
        source: &str,
        mut next_token: Option<Token>,
    ) -> Result<Range<usize>> {
        while let Some(token) = next_token {
            match token {
                Token::HexValue => {
                    return Ok(lex.span());
                }
                Token::DoubleQuote => {
                    // We know that quoted attribute names are always
                    // 4 characters long so we do this parsing differently
                    // as the parse_quoted_string() function needs to check
                    // for a terminating newline in order to handle
                    // nested quotes properly, without this
                    // parse_quoted_string() would also need to test
                    // for a terminating '<' as the start of an attribute type
                    let start = lex.span().end;
                    let remainder = lex.remainder();
                    if remainder.len() >= 4 {
                        let name = &remainder[0..4];
                        lex.bump(4);
                    }
                    let end_quote = lex.next();
                    if !matches!(end_quote, Some(Token::DoubleQuote)) {
                        return Err(Error::ParseAttributeNameQuote(
                            source[lex.span()].to_owned(),
                        ));
                    }
                    return Ok(start..lex.span().start);
                }
                _ => {}
            }
            next_token = lex.next();
        }
        Err(Error::ParseNotAttributeName(source[lex.span()].to_owned()))
    }

    fn parse_attribute_type(
        lex: &mut Lexer<Token>,
        source: &str,
        mut next_token: Option<Token>,
    ) -> Result<Range<usize>> {
        while let Some(token) = next_token {
            if let Token::Type = token {
                return Ok(lex.span());
            }
            next_token = lex.next();
        }
        Err(Error::ParseNotAttributeType(source[lex.span()].to_owned()))
    }

    fn parse_attribute_value<'a>(
        lex: &mut Lexer<Token>,
        source: &'a str,
        _attr_type: &AttributeType,
    ) -> Result<Value<'a>> {
        let token = lex.next();
        Self::parse_value(lex, source, token)
    }

    fn parse_value<'a>(
        lex: &mut Lexer<Token>,
        source: &'a str,
        token: Option<Token>,
    ) -> Result<Value<'a>> {
        if let Some(token) = token {
            match token {
                Token::Null => return Ok(Value::Null),
                Token::HexValue => {
                    let hex = &source[lex.span()];
                    if lex.remainder().starts_with(r#"  ""#) {
                        let next_token = lex.next();
                        let range = Self::parse_quoted_string(
                            lex, source, next_token,
                        )?;
                        let value = &source[range];
                        return Ok(Value::BlobString(hex, value));
                    }
                    return Ok(Value::Blob(hex));
                }
                Token::DoubleQuote => {
                    let range =
                        Self::parse_quoted_string(lex, source, Some(token))?;
                    let value = &source[range];
                    return Ok(Value::String(value));
                }
                _ => {
                    return Err(Error::ParseValue(
                        source[lex.span()].to_owned(),
                    ))
                }
            }
        }
        Err(Error::ParseValue(source[lex.span()].to_owned()))
    }

    fn parse_number(
        lex: &mut Lexer<Token>,
        source: &str,
        mut next_token: Option<Token>,
    ) -> Result<Range<usize>> {
        while let Some(token) = next_token {
            if let Token::Number = token {
                return Ok(lex.span());
            }
            next_token = lex.next();
        }
        Err(Error::ParseNotNumber(source[lex.span()].to_owned()))
    }
}

/// Collection of keychain entries.
#[derive(Debug)]
pub struct KeychainList<'s> {
    entries: Vec<KeychainEntry<'s>>,
}

impl<'s> KeychainList<'s> {
    /// Get the collection of entries.
    pub fn entries(&self) -> &[KeychainEntry<'s>] {
        self.entries.as_slice()
    }

    /// Get the number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Determine if this list is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.len() == 0
    }

    /// Find a generic password entry that can be used to verify
    /// a supplied password.
    pub fn first_generic_password(
        &self,
    ) -> Option<(&str, &str, &KeychainEntry<'s>)> {
        self.entries.iter().find_map(|entry| {
            if let Some(EntryClass::GenericPassword) = entry.class {
                if let (Some((_, attr_service)), Some((_, attr_account))) = (
                    entry.find_attribute_by_name(
                        AttributeName::SecServiceItemAttr,
                    ),
                    entry.find_attribute_by_name(
                        AttributeName::SecAccountItemAttr,
                    ),
                ) {
                    return Some((
                        attr_service.as_str(),
                        attr_account.as_str(),
                        entry,
                    ));
                }
            }
            None
        })
    }

    /// Attempt to find a generic password entry.
    pub fn find_generic_password(
        &self,
        service: &str,
        account: &str,
    ) -> Option<&KeychainEntry<'_>> {
        self.entries.iter().find(|entry| {
            if let Some(EntryClass::GenericPassword) = entry.class {
                if let (Some((_, attr_service)), Some((_, attr_account))) = (
                    entry.find_attribute_by_name(
                        AttributeName::SecServiceItemAttr,
                    ),
                    entry.find_attribute_by_name(
                        AttributeName::SecAccountItemAttr,
                    ),
                ) {
                    if attr_service.matches(service)
                        && attr_account.matches(account)
                    {
                        return true;
                    }
                }
            }
            false
        })
    }

    /// Attempt to find a generic password note.
    pub fn find_generic_note(
        &self,
        service: &str,
    ) -> Option<&KeychainEntry<'_>> {
        self.entries.iter().find(|entry| {
            if let Some(EntryClass::GenericPassword) = entry.class {
                if let (Some((_, attr_service)), Some((_, attr_type))) = (
                    entry.find_attribute_by_name(
                        AttributeName::SecServiceItemAttr,
                    ),
                    entry.find_attribute_by_name(
                        AttributeName::SecTypeItemAttr,
                    ),
                ) {
                    if attr_service.matches(service)
                        && attr_type.matches(NOTE_TYPE)
                    {
                        return true;
                    }
                }
            }
            false
        })
    }
}

/// Entry in a keychain list.
#[derive(Debug)]
pub struct KeychainEntry<'s> {
    /// The keychain path.
    keychain: &'s str,
    /// Keychain version.
    version: Option<&'s str>,
    /// Item class.
    class: Option<EntryClass>,
    /// Attributes mapping.
    attributes: HashMap<AttributeKey<'s>, Value<'s>>,
    /// Data for the entry.
    data: Option<Value<'s>>,
}

impl<'s> KeychainEntry<'s> {
    /// Attempt to find an attribute by name.
    pub fn find_attribute_by_name(
        &self,
        name: AttributeName<'_>,
    ) -> Option<(&AttributeType, &Value<'_>)> {
        self.attributes.iter().find_map(|(key, value)| {
            if key.0 == name {
                Some((&key.1, value))
            } else {
                None
            }
        })
    }

    /// Determine if this entry is a secure note.
    pub fn is_note(&self) -> bool {
        let type_attr =
            self.find_attribute_by_name(AttributeName::SecTypeItemAttr);
        if let Some((_, attr_type)) = type_attr {
            return attr_type.matches(NOTE_TYPE);
        }
        false
    }

    /// Attempt to get the entry data as a string
    /// for the generic password class.
    pub fn generic_data(&self) -> Result<Option<Cow<str>>> {
        if let Some(data) = &self.data {
            if let Some(EntryClass::GenericPassword) = self.class {
                if self.is_note() {
                    match data {
                        Value::BlobString(_, value) => {
                            return plist_secure_note(value, true);
                        }
                        _ => {}
                    }
                } else {
                    match data {
                        Value::String(value) => {
                            return Ok(Some(Cow::Borrowed(value)))
                        }
                        Value::BlobString(_, value) => {
                            return Ok(Some(Cow::Borrowed(value)))
                        }
                        _ => {}
                    }
                }
            }
        }
        Ok(None)
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
    /// Unknown attribute name.
    Unknown(&'s str),
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
            // Unknown
            "prot" => Ok(Self::Unknown(value)),
            "hpky" => Ok(Self::Unknown(value)),
            "issu" => Ok(Self::Unknown(value)),
            "skid" => Ok(Self::Unknown(value)),
            "snbr" => Ok(Self::Unknown(value)),
            "subj" => Ok(Self::Unknown(value)),
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
pub enum Value<'s> {
    /// Null value.
    Null,
    /// Time date value.
    TimeDate(&'s str),
    /// Quoted string value.
    String(&'s str),
    /// Uint32 value.
    Uint32(&'s str),
    /// Sint32 value.
    Sint32(&'s str),
    /// Hexadecimal encoded bytes followed by a quoted string value.
    BlobString(&'s str, &'s str),
    /// Hexadecimal encoded bytes.
    Blob(&'s str),
}

impl<'s> Value<'s> {
    /// Get this value as a string.
    pub fn as_str(&self) -> &str {
        match *self {
            Self::Null => "",
            Self::TimeDate(value) => value,
            Self::String(value) => value,
            Self::Uint32(value) => value,
            Self::Sint32(value) => value,
            Self::BlobString(_, value) => value,
            Self::Blob(value) => value,
        }
    }

    /// Determine if this value matches the given input.
    ///
    /// For the `BlobString` variant this matches against the blob value and
    /// ignores the hex number.
    pub fn matches(&self, input: &str) -> bool {
        match *self {
            Self::Null => false,
            Self::TimeDate(value) => value == input,
            Self::String(value) => value == input,
            Self::Uint32(value) => value == input,
            Self::Sint32(value) => value == input,
            Self::BlobString(_, value) => value == input,
            Self::Blob(value) => value == input,
        }
    }
}

#[cfg(test)]
mod test {
    use super::{unescape_octal, KeychainParser};
    use anyhow::Result;

    #[test]
    fn keychain_unescape_octal() -> Result<()> {
        let expected =
            std::fs::read_to_string("fixtures/plist-data-unescaped.txt")?;
        let contents =
            std::fs::read_to_string("fixtures/plist-data-escaped.txt")?;
        let plist = unescape_octal(&contents)?;
        /*
        std::fs::write(
            "fixtures/plist-data-unescaped.txt", plist.as_ref())?;
        */
        assert_eq!(&expected, plist.as_ref());
        Ok(())
    }

    #[test]
    fn keychain_parse_basic() -> Result<()> {
        let contents = std::fs::read_to_string("fixtures/sos-mock.txt")?;
        let parser = KeychainParser::new(&contents);
        let list = parser.parse()?;

        let password_entry =
            list.find_generic_password("test password", "test account");
        assert!(password_entry.is_some());

        let note_entry = list.find_generic_note("test note");
        assert!(note_entry.is_some());
        Ok(())
    }

    #[test]
    fn keychain_parse_certificate() -> Result<()> {
        let contents =
            std::fs::read_to_string("fixtures/mock-certificate.txt")?;
        let parser = KeychainParser::new(&contents);
        let list = parser.parse()?;
        Ok(())
    }

    #[test]
    fn keychain_parse_data() -> Result<()> {
        let contents = std::fs::read_to_string("fixtures/sos-mock-data.txt")?;
        let parser = KeychainParser::new(&contents);
        let list = parser.parse()?;

        let password_entry =
            list.find_generic_password("test password", "test account");
        assert!(password_entry.is_some());

        let password_data =
            password_entry.as_ref().unwrap().generic_data()?;
        assert_eq!("mock-password-value", password_data.unwrap());

        let note_entry = list.find_generic_note("test note");
        assert!(note_entry.is_some());

        let note_data = note_entry.as_ref().unwrap().generic_data()?;
        assert_eq!("mock-secure-note-value", note_data.unwrap());

        Ok(())
    }
}
