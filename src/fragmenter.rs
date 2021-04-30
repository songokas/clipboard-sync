use serde::{Deserialize, Serialize};

use crate::errors::ConnectionError;

#[derive(Serialize, Deserialize, Debug)]
pub struct Frame
{
    pub index: u32,
    pub total: u16,
    pub data: Vec<u8>,
}

pub fn data_to_frame(
    index: u32,
    total: u16,
    data: &[u8],
    max_payload: usize,
) -> Result<Vec<u8>, ConnectionError>
{
    let size = data.len();
    let from = index as usize * max_payload;
    let to = if from + max_payload > size {
        size
    } else {
        from + max_payload
    };

    let frame = Frame {
        index: index,
        total: total as u16,
        data: data[from..to].to_vec(),
    };

    let bytes = bincode::serialize(&frame)
        .map_err(|err| ConnectionError::InvalidBuffer((*err).to_string()))?;
    return Ok(bytes);
}
