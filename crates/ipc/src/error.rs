use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    /// Error reading server response.
    #[error("no server response")]
    NoResponse,

    /// Error generated by the protobuf library when encoding.
    #[error(transparent)]
    ProtoBufEncode(#[from] prost::EncodeError),

    /// Error generated by the protobuf library when decoding.
    #[error(transparent)]
    ProtoBufDecode(#[from] prost::DecodeError),

    /// Error generated by the protobuf library when converting enums.
    #[error(transparent)]
    ProtoEnum(#[from] prost::UnknownEnumValue),

    #[error(transparent)]
    Io(#[from] std::io::Error),
}
