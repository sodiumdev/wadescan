use std::fmt::Display;

use base64::Engine;
use serde::{Deserialize, Serialize};

#[repr(u8)]
pub enum PingParseError {
    Invalid,
    Incomplete,
}

#[inline(always)]
pub fn build_latest_request(protocol_version: i32, hostname: &str, port: u16) -> Vec<u8> {
    let mut buffer = vec![0x00];
    write_varint(&mut buffer, protocol_version);
    write_varint(&mut buffer, hostname.len() as i32);

    buffer.extend_from_slice(hostname.as_bytes());
    buffer.extend_from_slice(&[(port >> 8) as u8, (port & 0b1111_1111) as u8, 0x01]);

    let mut full_buffer = vec![];
    write_varint(&mut full_buffer, buffer.len() as i32);
    full_buffer.append(&mut buffer);
    full_buffer.extend_from_slice(&[1, 0x00]);

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
fn read_varint(ip: &mut usize, buffer: &[u8]) -> Option<i32> {
    let mut res = 0;
    for i in 0..5 {
        let byte = buffer.get(*ip)?;
        *ip += 1;

        res |= ((byte & 0b0111_1111) as i32) << (7 * i);
        if byte & 0b1000_0000 == 0 {
            break;
        }
    }

    Some(res)
}

#[inline(always)]
pub fn parse_response(response: &[u8]) -> Result<Vec<u8>, PingParseError> {
    let mut ip = 0;
    for _ in 0..5 {
        let byte = response.get(ip).ok_or(PingParseError::Invalid)?;
        ip += 1;

        if byte & 0b1000_0000 == 0 {
            break;
        }
    }

    let packet_id = read_varint(&mut ip, response).ok_or(PingParseError::Invalid)?;
    let response_length = read_varint(&mut ip, response).ok_or(PingParseError::Invalid)?;
    if packet_id != 0x00 || response_length < 0 {
        return Err(PingParseError::Invalid);
    }

    let status_buffer = &response[ip..];
    if status_buffer.len() < response_length as usize {
        return Err(PingParseError::Incomplete);
    }

    Ok(status_buffer.to_vec())
}

#[derive(Debug)]
/// The ping error type.
pub enum Error {
    /// Returned when I/O (especially networking) failed.
    Io(std::io::Error),
    /// Returned when the response cannot be recognized.
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

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub(crate) struct RawLatest {
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
/// A ping response returned from server.
/// The response schema can be altered anytime, thus `#[non_exhaustive]`.
pub struct Response {
    /// The version name of the server.
    pub version: String,
    /// The protocol number of the server.
    /// See also [the minecraft protocol wiki](https://wiki.vg/Protocol_version_numbers) for the actual values.
    pub protocol: i32,
    /// If the server requires the user to sign chat messages with their private key.
    pub enforces_secure_chat: Option<bool>,
    pub previews_chat: Option<bool>,
    /// The maximum number of the connected players.
    pub max_players: usize,
    /// The number of the players currently connected.
    pub online_players: usize,
    /// The sample of the connected players.
    /// Note that it can be `None` even if some players are connected.
    pub sample: Option<Vec<Player>>,
    /// The description (aka MOTD) of the server.
    /// See also [the minecraft protocol wiki](https://wiki.vg/Chat#Current_system_.28JSON_Chat.29) for the [`Chat`](Chat) format.
    pub description: Chat,
    /// The favicon of the server in PNG format.
    pub favicon: Option<Vec<u8>>,
    /// The mod information object used in FML protocol (version 1.7 - 1.12).
    /// See also [the minecraft protocol wiki](https://wiki.vg/Minecraft_Forge_Handshake#FML_protocol_.281.7_-_1.12.29)
    /// for the [`ModInfo`](ModInfo) format.
    pub mod_info: Option<ModInfo>,
    /// The forge information object used in FML2 protocol (version 1.13 - current).
    /// See also [the minecraft protocol wiki](https://wiki.vg/Minecraft_Forge_Handshake#FML2_protocol_.281.13_-_Current.29)
    /// for the [`ForgeData`](ForgeData) format.
    pub forge_data: Option<ForgeData>,
    /// The raw response returned from the server.
    /// It is `Vec<u8>` because server is not guaranteed to return valid UTF-8,
    /// even not a json at all.
    #[serde(skip)]
    pub(crate) raw: Vec<u8>,
}

impl Response {
    /// The raw response returned from the server.
    /// It is `Vec<u8>` because server is not guaranteed to return valid UTF-8,
    /// even not a json at all.
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }
}

impl TryFrom<RawLatest> for Response {
    type Error = Error;

    fn try_from(raw: RawLatest) -> Result<Self, Self::Error> {
        let favicon = if let Some(favicon) = raw.favicon {
            // normal server favicon should start with "data:image/png;base64,"
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
/// The sample players' information.
pub struct Player {
    /// The name of the player.
    pub name: String,
    /// The uuid of the player.
    /// Normally used to identify a player.
    pub id: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(untagged)]
pub(crate) enum RawDescription {
    Raw(String),
    Chat(Chat),
}

#[derive(Debug, Deserialize, Serialize, Clone)]
/// The mod information object used in FML protocol (version 1.7 - 1.12).
pub struct ModInfo {
    #[serde(rename = "type")]
    /// The field `type` of `modinfo`. It should be FML if forge is installed.
    pub mod_type: String,
    #[serde(rename = "modList")]
    /// The list of the mod installed on the server.
    /// See also [`ModInfoItem`](ModInfoItem)
    pub mod_list: Vec<ModInfoItem>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
/// The information of an installed mod.
pub struct ModInfoItem {
    #[serde(rename = "modid")]
    /// The id of the mod.
    pub mod_id: String,
    /// The version of the mod.
    pub version: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
/// The forge information object used in FML2 protocol (version 1.13 - current).
pub struct ForgeData {
    /// The list of the channels used by the mods.
    /// See [the minecraft protocol wiki](https://wiki.vg/Plugin_channels) for more information.
    pub channels: Vec<ForgeChannel>,
    /// The list of the mods installed on the server.
    pub mods: Vec<ForgeMod>,
    #[serde(rename = "fmlNetworkVersion")]
    pub fml_network_version: i32,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
/// The information of the channels used by the mods.
///
/// See [the minecraft protocol wiki](https://wiki.vg/Plugin_channels) for more information.
/// Unfortunately, the exact semantics of its field is currently not found.
/// We do not guarantee the document is right, and you should re-check the values you've received.
pub struct ForgeChannel {
    /// The namespaced key of the channel
    pub res: String,
    /// The version of the channel
    pub version: String,
    /// `true` if it is required
    pub required: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
/// The information of an installed mod.
pub struct ForgeMod {
    #[serde(rename = "modId")]
    /// The id of the mod.
    pub mod_id: String,
    #[serde(rename = "modmarker")]
    /// The version of the mod.
    pub mod_marker: String,
}

#[derive(Debug, Deserialize, Serialize, Default, Clone)]
/// The chat component used in the server description.
///
/// See also [the minecraft protocol wiki](https://wiki.vg/Chat#Current_system_.28JSON_Chat.29).
pub struct Chat {
    /// The text which this `Chat` object holds.
    pub text: String,
    #[serde(default)]
    /// `true` if the text *and* the extras should be __bold__.
    pub bold: bool,
    #[serde(default)]
    /// `true` if the text *and* the extras should be *italic*.
    pub italic: bool,
    #[serde(default)]
    /// `true` if the text *and* the extras should be <u>underlined</u>.
    pub underlined: bool,
    #[serde(default)]
    /// `true` if the text *and* the extras should have a <strike>strikethrough</strike>.
    pub strikethrough: bool,
    #[serde(default)]
    /// `true` if the text *and* the extras should look obfuscated.
    pub obfuscated: bool,
    /// The color which the text and the extras should have.
    /// `None` to use default color.
    pub color: Option<String>,
    #[serde(default)]
    /// The extra text components following this text.
    /// They should inherit this chat component's properties (bold, italic, etc.) but can also override the properties.
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
