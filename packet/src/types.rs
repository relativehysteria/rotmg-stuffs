use crate::Packet;

/// Sent to prompt the server to accept the conneciton of an account.
#[derive(Debug, Packet)]
pub struct Hello {
    // TODO: Implement known map values.
    /// The ID of the map to connect to.
    pub map_id: i32,

    /// The current build version of the game.
    pub build_version: String,

    /// The access token used to log in.
    pub access_token: String,

    /// The time at which the `key` was generated.
    pub key_time: u32,

    /// The key of the map to connect to.
    ///
    /// When a `Reconnect` packet is received, the client is given the new
    /// socket address to which it should connect, together with the key
    /// required to verify the connection.
    pub key: Vec<u8>,

    /// The platform the user is using.
    pub user_platform: String,

    /// The platform the game is played on.
    pub play_platform: String,

    /// The client token of the Steam client.
    ///
    /// Empty for standalone version of the game.
    pub platform_token: String,

    /// The client token (hwid) of the Unity client.
    pub hwid_token: String,

    /// Hardcoded token for all `Hello` packets.
    pub hardcoded_token: String,
}

impl Hello {
    /// The value of the hardcoded token string at the end of the packet.
    #[allow(unused)]
    const HARDCODED_TOKEN: &str = "XQpu8CWkMehb5rLVP3DG47FcafExRUvg";
}
