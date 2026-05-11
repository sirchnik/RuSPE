use libtock::platform;
use libtock::platform::AllowRo;
use libtock::platform::allow_rw::AllowRw;
use libtock::platform::share;
use libtock::platform::{DefaultConfig, ErrorCode, Syscalls};

pub struct SpeDriver<S: Syscalls, C: Config = DefaultConfig>(S, C);

impl<S: Syscalls, C: Config> SpeDriver<S, C> {
    pub fn exists() -> Result<(), ErrorCode> {
        S::command(DRIVER_NUM, cmd::EXISTS, 0, 0).to_result()
    }

    pub fn initial_attest_get_token_sync(
        challenge: &[u8],
        token_buf: &mut [u8],
    ) -> Result<usize, ErrorCode> {
        let token_capacity = token_buf.len();

        if challenge.is_empty() || challenge.len() > u32::MAX as usize {
            return Err(ErrorCode::Invalid);
        }
        if token_capacity == 0 {
            return Err(ErrorCode::NoMem);
        }

        share::scope::<
            (
                AllowRw<_, DRIVER_NUM, { rw_allow::TOKEN }>,
                AllowRo<_, DRIVER_NUM, { ro_allow::CHALLENGE }>,
            ),
            _,
            _,
        >(|handle| {
            let (allow_rw, allow_ro) = handle.split();
            S::allow_rw::<C, DRIVER_NUM, { rw_allow::TOKEN }>(allow_rw, token_buf)?;
            S::allow_ro::<C, DRIVER_NUM, { ro_allow::CHALLENGE }>(allow_ro, challenge)?;

            let token_len = S::command(
                DRIVER_NUM,
                cmd::INITIAL_ATTEST_GET_TOKEN,
                challenge.len() as u32,
                0,
            )
            .to_result::<u32, ErrorCode>()?;

            let token_len = token_len as usize;
            if token_len > token_capacity {
                return Err(ErrorCode::Size);
            }
            Ok(token_len)
        })
    }
}

pub trait Config: platform::allow_ro::Config + platform::allow_rw::Config {}
impl<T: platform::allow_ro::Config + platform::allow_rw::Config> Config for T {}

const DRIVER_NUM: u32 = 0xA0000;

mod ro_allow {
    pub const CHALLENGE: u32 = 0;
}

mod rw_allow {
    pub const TOKEN: u32 = 0;
}

mod cmd {
    pub const EXISTS: u32 = 0;
    pub const INITIAL_ATTEST_GET_TOKEN: u32 = 1;
}
