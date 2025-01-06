#[repr(u8)]
pub enum PingError {
    Invalid,
    Incomplete,
}

#[inline(always)]
pub fn build_latest_request(protocol_version: i32, hostname: &str, port: u16) -> Vec<u8> {
    let mut buffer = vec![0x00];
    write_varint(&mut buffer, protocol_version);
    write_varint(&mut buffer, hostname.len() as i32);

    buffer.extend_from_slice(hostname.as_bytes());
    buffer.extend_from_slice(&[
        (port >> 8) as u8,
        (port & 0b1111_1111) as u8,
        0x01,
    ]);

    let mut full_buffer = vec![];
    write_varint(&mut full_buffer, buffer.len() as i32);
    full_buffer.append(&mut buffer);
    full_buffer.extend_from_slice(&[
        1,
        0x00,
    ]);

    full_buffer
}

#[inline(always)]
fn write_varint(writer: &mut Vec<u8>, mut value: i32) {
    let mut buffer = [0];
    if value == 0 {
        writer.extend_from_slice(&buffer);
    }

    while value != 0 {
        buffer[0] = (value & 0b0111_1111) as u8;
        value = (value >> 7) & (i32::MAX >> 6);
        if value != 0 {
            buffer[0] |= 0b1000_0000;
        }

        writer.extend_from_slice(&buffer);
    }
}

#[inline(always)]
fn read_varint(ip: &mut usize, buffer: &[u8]) -> i32 {
    let mut res = 0;
    for i in 0..5 {
        let byte = buffer[*ip];
        *ip += 1;

        res |= ((byte & 0b0111_1111) as i32) << (7 * i);
        if byte & 0b1000_0000 == 0 {
            break
        }
    }

    res
}

#[inline(always)]
pub fn parse_response(response: &[u8]) -> Result<Vec<u8>, PingError> {
    let mut ip = 0;
    for _ in 0..5 {
        let byte = response[ip];
        ip += 1;

        if byte & 0b1000_0000 == 0 {
            break
        }
    }

    let packet_id = read_varint(&mut ip, response);
    let response_length = read_varint(&mut ip, response);
    if packet_id != 0x00 || response_length < 0 {
        return Err(PingError::Invalid)
    }

    let status_buffer = &response[ip..];
    if status_buffer.len() < response_length as usize {
        return Err(PingError::Incomplete)
    }

    Ok(status_buffer.to_vec())
}
