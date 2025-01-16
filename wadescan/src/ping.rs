use std::fmt::Display;
use base64::Engine;
use serde::{Deserialize, Serialize};

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

// thanks craftping

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct RawLatest {
    pub version: Version,
    pub players: Players,
    pub description: RawDescription,
    pub favicon: Option<String>,
    
    #[serde(rename = "enforcesSecureChat")]
    pub enforces_secure_chat: Option<bool>,
    
    #[serde(rename = "previewsChat")]
    pub previews_chat: Option<bool>,
    
    #[serde(rename = "modinfo")]
    pub mod_info: Option<ModInfo>,
    
    #[serde(rename = "forgeData")]
    pub forge_data: Option<ForgeData>,
    
    #[serde(skip)]
    pub raw_json: Vec<u8>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[non_exhaustive]
pub struct Response {
    pub version: String,
    pub protocol: i32,
    pub enforces_secure_chat: Option<bool>,
    pub previews_chat: Option<bool>,
    pub max_players: usize,
    pub online_players: usize,
    pub sample: Option<Vec<Player>>,
    pub description: Chat,
    pub favicon: Option<Vec<u8>>,
    pub mod_info: Option<ModInfo>,
    pub forge_data: Option<ForgeData>,
    
    #[serde(skip)]
    pub(crate) raw: Vec<u8>,
}

impl Response {
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }
}

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    UnsupportedProtocol,
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(io) => io.fmt(f),
            Self::UnsupportedProtocol => write!(f, "unsupported protocol"),
        }
    }
}

impl TryFrom<RawLatest> for Response {
    type Error = Error;

    fn try_from(raw: RawLatest) -> Result<Self, Self::Error> {
        let favicon = if let Some(favicon) = raw.favicon {
            let slice = favicon.get(22..).ok_or(Error::UnsupportedProtocol)?;
            Some(
                base64::engine::general_purpose::STANDARD
                    .decode(slice)
                    .map_err(|_| Error::UnsupportedProtocol)?,
            )
        } else {
            None
        };
        Ok(Self {
            version: raw.version.name,
            protocol: raw.version.protocol,
            enforces_secure_chat: raw.enforces_secure_chat,
            previews_chat: raw.previews_chat,
            max_players: raw.players.max,
            online_players: raw.players.online,
            sample: raw.players.sample,
            description: raw.description.into(),
            favicon,
            mod_info: raw.mod_info,
            forge_data: raw.forge_data,
            raw: raw.raw_json,
        })
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub(crate) struct Version {
    pub name: String,
    pub protocol: i32,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub(crate) struct Players {
    pub max: usize,
    pub online: usize,
    pub sample: Option<Vec<Player>>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Player {
    pub name: String,
    pub id: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(untagged)]
pub(crate) enum RawDescription {
    Raw(String),
    Chat(Chat),
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ModInfo {
    #[serde(rename = "type")]
    pub mod_type: String,
    
    #[serde(rename = "modList")]
    pub mod_list: Vec<ModInfoItem>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ModInfoItem {
    #[serde(rename = "modid")]
    pub mod_id: String,
    pub version: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ForgeData {
    pub channels: Vec<ForgeChannel>,
    pub mods: Vec<ForgeMod>,
    
    #[serde(rename = "fmlNetworkVersion")]
    pub fml_network_version: i32,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ForgeChannel {
    pub res: String,
    pub version: String,
    pub required: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ForgeMod {
    #[serde(rename = "modId")]
    pub mod_id: String,
    
    #[serde(rename = "modmarker")]
    pub mod_marker: String,
}

#[derive(Debug, Deserialize, Serialize, Default, Clone)]
pub struct Chat {
    pub text: String,
    
    #[serde(default)]
    pub bold: bool,
    
    #[serde(default)]
    pub italic: bool,
    
    #[serde(default)]
    pub underlined: bool,
    
    #[serde(default)]
    pub strikethrough: bool,
    
    #[serde(default)]
    pub obfuscated: bool,
    pub color: Option<String>,
    
    #[serde(default)]
    pub extra: Vec<Chat>,
}

impl From<RawDescription> for Chat {
    fn from(description: RawDescription) -> Self {
        match description {
            RawDescription::Chat(chat) => chat,
            RawDescription::Raw(text) => Chat {
                text,
                ..Default::default()
            },
        }
    }
}
