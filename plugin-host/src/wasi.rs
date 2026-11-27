//! WASI as the helper offers it (spec section 5, "Imports"): `wasi:clocks` and `wasi:random`
//! (0.2.x) are real; every other `wasi:*` import is a stub that traps when called. Same code as
//! the test host (`plugins/testhost/src/wasi.rs`), so a plugin behaves the same in both.

use std::time::{SystemTime, UNIX_EPOCH};

use wasmtime::component::{ComponentType, Linker, Lower};
use wasmtime::StoreContextMut;

use crate::runtime::State;

const RANDOM_MAX: u64 = 64 * 1024;

#[derive(ComponentType, Lower)]
#[component(record)]
struct Datetime {
    seconds: u64,
    nanoseconds: u32,
}

fn random_bytes(len: u64) -> wasmtime::Result<Vec<u8>> {
    if len > RANDOM_MAX {
        wasmtime::bail!("random: more than {RANDOM_MAX} bytes asked in one call");
    }
    let mut bytes = vec![0u8; len as usize];
    getrandom::fill(&mut bytes).map_err(|e| wasmtime::format_err!("random: {e}"))?;
    Ok(bytes)
}

fn random_u64() -> wasmtime::Result<u64> {
    let mut bytes = [0u8; 8];
    getrandom::fill(&mut bytes).map_err(|e| wasmtime::format_err!("random: {e}"))?;
    Ok(u64::from_le_bytes(bytes))
}

/// Defines the real clock and random functions under the exact name the component imports.
pub fn add(linker: &mut Linker<State>, name: &str) -> wasmtime::Result<()> {
    let Some((base, version)) = name.split_once('@') else { return Ok(()) };
    if !version.starts_with("0.2.") {
        return Ok(());
    }
    type Cx<'a> = StoreContextMut<'a, State>;
    match base {
        "wasi:clocks/monotonic-clock" => {
            let mut inst = linker.instance(name)?;
            inst.func_wrap("now", |cx: Cx<'_>, (): ()| Ok((cx.data().started.elapsed().as_nanos() as u64,)))?;
            inst.func_wrap("resolution", |_: Cx<'_>, (): ()| Ok((1u64,)))?;
        }
        "wasi:clocks/wall-clock" => {
            let mut inst = linker.instance(name)?;
            inst.func_wrap("now", |_: Cx<'_>, (): ()| {
                let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
                Ok((Datetime { seconds: now.as_secs(), nanoseconds: now.subsec_nanos() },))
            })?;
            inst.func_wrap("resolution", |_: Cx<'_>, (): ()| Ok((Datetime { seconds: 0, nanoseconds: 1 },)))?;
        }
        "wasi:random/random" => {
            let mut inst = linker.instance(name)?;
            inst.func_wrap("get-random-bytes", |_: Cx<'_>, (len,): (u64,)| Ok((random_bytes(len)?,)))?;
            inst.func_wrap("get-random-u64", |_: Cx<'_>, (): ()| Ok((random_u64()?,)))?;
        }
        "wasi:random/insecure" => {
            let mut inst = linker.instance(name)?;
            inst.func_wrap("get-insecure-random-bytes", |_: Cx<'_>, (len,): (u64,)| Ok((random_bytes(len)?,)))?;
            inst.func_wrap("get-insecure-random-u64", |_: Cx<'_>, (): ()| Ok((random_u64()?,)))?;
        }
        "wasi:random/insecure-seed" => {
            let mut inst = linker.instance(name)?;
            inst.func_wrap("insecure-seed", |_: Cx<'_>, (): ()| Ok(((random_u64()?, random_u64()?),)))?;
        }
        _ => {}
    }
    Ok(())
}
