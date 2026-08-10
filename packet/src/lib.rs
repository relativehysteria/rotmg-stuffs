//! Utilities for working with game packets.

pub mod reader;
pub mod writer;

pub use writer::{PacketWriter, PacketEncode, EncodeError};
pub use reader::{PacketReader, PacketDecode, DecodeError};

// Required to make the `Packet` derive macro work.
extern crate self as packet;

// Export the Packet derive macro here. These are allowed to have the same name
// because they're different namespaces; the `Packet` trait (implemented below)
// lives in the _type namespace_ whereas the derive macro lives in the
// _macro namespace_.
pub use packet_derive::Packet;

/// A complete packet that can be encoded to and decoded from the packet wire
/// format.
///
/// This trait is automatically implemented for every type that implements
/// [`PacketEncode`] and [`PacketDecode`].
///
/// Packet fields are encoded and decoded in their declaration order when using
/// the [`Packet`](derive@Packet) derive macro.
///
/// # Examples
///
/// ```ignore
/// #[derive(Packet)]
/// struct Hello {
///     game_id: i32,
///     build_version: String,
/// }
/// ```
pub trait Packet: PacketEncode + PacketDecode {}

// Auto impl for all types.
impl<T: PacketEncode + PacketDecode> Packet for T {}

/// NOTE: Put here for now; testing whether decryption works! I'll put it into a
/// better place later.
#[derive(Debug, Packet)]
pub struct Hello {
    pub game_id: i32,
    pub build_version: String,
    pub access_token: String,
    pub key_time: u32,
    pub key: Vec<u8>,
    pub user_platform: String,
    pub play_platform: String,
    pub platform_token: String,
    pub client_token: String,
    pub user_token: String,
}

macro_rules! packet_types {
    (
        $(
            $name:ident = $id:expr
        ),* $(,)?
    ) => {
        #[repr(u8)]
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        #[doc = "Specific type of a game packet."]
        pub enum PacketType {
            $(
                $name = ($id & 0xFF) as u8,
            )*
        }

        impl TryFrom<u8> for PacketType {
            type Error = u8;

            fn try_from(value: u8) -> Result<Self, Self::Error> {
                $(
                    if value == (($id & 0xFF) as u8) {
                        return Ok(Self::$name);
                    }
                )*

                Err(value)
            }
        }
    };
}

packet_types! {
    Failure = 0,
    Teleport = 1,
    ClaimLoginRewardMsg = 3,
    DeletePet = 4,
    RequestTrade = 5,
    QuestFetchResponse = 6,
    JoinGuild = 7,
    Ping = 8,
    PlayerText = 9,
    Tick = 10,
    ShowEffect = 11,
    ServerPlayerShoot = 12,
    UseItem = 13,
    TradeAccepted = 14,
    GuildRemove = 15,
    PetUpgradeRequest = 16,
    Goto = 18,
    InvDrop = 19,
    OtherHit = 20,
    NameResult = 21,
    BuyResult = 22,
    HatchPet = 23,
    ActivePetUpdateRequest = 24,
    EnemyHit = 25,
    GuildResult = 26,
    EditAccountList = 27,
    TradeChanged = 28,
    PlayerShoot = 30,
    Pong = 31,
    PetChangeSkinMsg = 33,
    TradeDone = 34,
    EnemyShoot = 35,
    AcceptTrade = 36,
    ChangeGuildRank = 37,
    PlaySound = 38,
    VerifyEmail = 39,
    SquareHit = 40,
    NewAbility = 41,
    Update = 42,
    Text = 44,
    Reconnect = 45,
    Death = 46,
    UsePortal = 47,
    QuestRoomMsg = 48,
    AllyShoot = 49,
    Reskin = 51,
    ResetDailyQuests = 52,
    PetChangeFormMsg = 53,
    InvSwap = 55,
    ChangeTrade = 56,
    Create = 57,
    QuestRedeem = 58,
    CreateGuild = 59,
    SetCondition = 60,
    Load = 61,
    TickAck = 62,
    KeyInfoResponse = 63,
    Aoe = 64,
    GotoAck = 65,
    GlobalNotification = 66,
    Notification = 67,
    ClientStat = 69,
    Hello = 74,
    Damage = 75,
    ActivePetUpdate = 76,
    InvitedToGuild = 77,
    PetYardUpdate = 78,
    PasswordPrompt = 79,
    UpdateAck = 81,
    QuestObjId = 82,
    Pic = 83,
    RealmHeroLeftMsg = 84,
    Buy = 85,
    TradeStart = 86,
    EvolvePet = 87,
    TradeRequested = 88,
    AoeAck = 89,
    PlayerHit = 90,
    CancelTrade = 91,
    MapInfo = 92,
    LoginRewardMsg = 93,
    KeyInfoRequest = 94,
    InvResult = 95,
    QuestRedeemResponse = 96,
    ChooseName = 97,
    QuestFetchAsk = 98,
    AccountList = 99,
    CreateSuccess = 101,
    CheckCredits = 102,
    GroundDamage = 103,
    GuildInvite = 104,
    Escape = 105,
    File = 106,
    ReskinUnlock = 107,
    NewCharacterInformation = 108,
    UnlockInformation = 109,
    QueueInformation = 112,
    QueueCancel = 113,
    ExaltationBonusChanged = 114,
    RedeemExaltationReward = 115,
    VaultUpdate = 117,
    ForgeRequest = 118,
    ForgeResult = 119,
    ForgeUnlockedBlueprints = 120,
    ShootAck = 121,
    ChangeAllyShoot = 122,
    GetPlayersListMessage = 123,
    ModeratorActionMessage = 124,
    CreepMoveMessage = 126,
    CustomMapDelete = 129,
    CustomMapList = 131,
    CreepHit = 133,
    PlayerCallout = 134,
    BuyRefinement = 136,
    Dash = 137,
    DashAck = 138,
    Stats = 139,
    BuyCustomisationSocket = 140,
    FavourPet = 145,
    SkinRecycle = 146,
    DamageBoost = 148,
    ClaimBattlePass = 149,
    ClaimBpMilestoneResult = 150,
    BoostBpMilestone = 151,
    ConvertSeasonalCharacter = 154,
    Retitle = 155,
    SetGraveStone = 156,
    SetAbility = 157,
    Emote = 159,
    BuyEmote = 160,
    SetTrackedSeason = 162,
    ClaimMission = 163,
    Stasis = 166,
    SetDiscoverable = 167,
    RealmScoreUpdate = 169,
    ClaimRewardsInfoPrompt = 170,
    ClaimChestReward = 171,
    ChestRewardResult = 172,
    UnlockEnchantmentSlot = 173,
    UnlockEnchantment = 175,
    ApplyEnchantment = 177,
    ActivateCrucible = 180,
    CrucibleRequest = 182,
    CrucibleResponse = 183,
    UpgradeEnchanter = 185,
    UpgradeEnchantment = 187,
    RerollAllEnchantments = 189,
    ResetEnchantmentRerollCount = 191,
    CreatePartyMessage = 200,
    PartyActionResult = 204,
    PartyAction = 207,
    IncomingPartyInvite = 208,
    PartyInviteResponse = 209,
    IncomingPartyMemberInfo = 210,
    PartyMemberAdded = 212,
    PartyListMessage = 214,
    PartyJoinRequest = 215,
    PartyRequestResponse = 217,
    ForReconnect = 218,
    LoadingScreen = 222,
    IpAddress = 1000,
}
