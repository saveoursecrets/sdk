use binary_stream::{
    BinaryReader, BinaryResult, BinaryWriter, Decode, Encode,
};
use serde::ser::SerializeTuple;
use std::{
    hash::Hasher as StdHasher,
    io::{Read, Seek, Write},
};

use rs_merkle::{algorithms::Sha256, MerkleProof};

use crate::commit::CommitProof;

impl Encode for CommitProof {
    fn encode<W: Write + Seek>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> BinaryResult<()> {
        writer.write_bytes(self.root)?;
        let proof_bytes = self.proof.to_bytes();
        writer.write_u32(proof_bytes.len() as u32)?;
        writer.write_bytes(&proof_bytes)?;

        writer.write_u32(self.length as u32)?;
        writer.write_u32(self.indices.start as u32)?;
        writer.write_u32(self.indices.end as u32)?;
        Ok(())
    }
}

impl Decode for CommitProof {
    fn decode<R: Read + Seek>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> BinaryResult<()> {
        let root_hash: [u8; 32] =
            reader.read_bytes(32)?.as_slice().try_into()?;
        self.root = root_hash;
        let length = reader.read_u32()?;
        let proof_bytes = reader.read_bytes(length as usize)?;
        let proof = MerkleProof::<Sha256>::from_bytes(&proof_bytes)
            .map_err(Box::from)?;

        self.proof = proof;
        self.length = reader.read_u32()? as usize;
        let start = reader.read_u32()?;
        let end = reader.read_u32()?;

        // TODO: validate range start is <= range end

        self.indices = start as usize..end as usize;
        Ok(())
    }
}
