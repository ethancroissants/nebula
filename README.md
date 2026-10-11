# ✦ Nebula

**A sleek script executor for [Sober](https://sober.vinegarhq.org) (Roblox on Linux).**

Nebula is a modern, native GUI + injected hook that attaches to Sober's game
process and executes Luau scripts in the live Roblox VM — no root, no VM, no
Windows.

```
curl -fsSL https://raw.githubusercontent.com/ethancroissants/nebula/main/install.sh | sh
```

---

## What it looks like

- Deep-space dark theme with an indigo→violet gradient header
- Code editor with line numbers and Lua syntax highlighting
- Live console that streams output from *inside* the game
- One-click **Attach**, one-click **Execute** (or press F5)

## How it works

```
┌──────────────┐    writes     ┌──────────────────────┐
│ Nebula (GUI) │──────────────▶│ ~/.nebula/queue/*.lua│
└──────────────┘               └──────────┬───────────┘
      flatpak override                    │ poll (200 ms)
      LD_PRELOAD=libnebula_hook.so        ▼
┌──────────────────────────────────────────────────────┐
│ Sober game process                                   │
│   libnebula_hook.so                                  │
│     • dlsym()s the Luau API out of libSoberRuntime.so│
│     • hooks lua_pcall → captures the lua_State*      │
│     • runs queued scripts via loadstring + pcall     │
└──────────────────────────────────────────────────────┘
```

The hook is injected through Sober's own Flatpak sandbox using
`flatpak override --user --env=LD_PRELOAD=...` — the same mechanism Sober uses
for its internal `libbadcpu.so` CPU-feature shim. The GUI never touches process
memory; the file queue is the entire transport, which keeps the design simple
and crash-safe.

### Reverse-engineering notes (Sober is closed-source)

Community RE ([sober-oss](https://github.com/Z3ki/sober-oss)) established:

| Sober component | Role |
|---|---|
| `sober` (Rust) | Translates the Android ARM64 Roblox binary to x86-64 |
| `libloader.so` | Forks, sandboxes and spawns the game binary |
| `libbadcpu.so` | SIGILL-based x86 instruction emulator (LD_PRELOAD'ed by Sober itself) |
| `libSoberRuntime.so` | Hosts the Luau VM — exports `lua_*` / `luaL_*` C symbols |

Because the Luau C API is **exported**, Nebula resolves it with `dlsym` at
runtime instead of fragile byte-pattern scans — this keeps working across
Roblox client updates.

### Verified end-to-end

`tests/run_e2e_test.sh` builds a stub `libSoberRuntime.so` with the same
exported Luau symbols plus a host process, preloads the real hook into it, and
verifies the full pipeline (constructor → symbol resolution → trampoline
installation → state capture → script execution → log round-trip) without
needing Sober or Roblox installed:

```
$ ./tests/run_e2e_test.sh
✦ E2E TEST PASSED
```

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/ethancroissants/nebula/main/install.sh | sh
```

The installer:
1. Detects your distro (apt/dnf/pacman/zypper/apk) and installs `flatpak` + `gtk3`
2. Downloads the latest prebuilt bundle (GUI binary + hook `.so`)
3. Installs to `~/.local/lib/nebula`, symlinks `nebula` into `~/.local/bin`
4. Installs Sober from Flathub if it's missing

Supported: Ubuntu, Debian, Fedora, Arch, openSUSE, Alpine (x86-64; Sober
requires SSE4.1).

Releases are built automatically by GitHub Actions (`.github/workflows/release.yml`)
whenever a `v*` tag is pushed — the workflow attaches
`nebula-linux-x86_64.tar.gz` to the GitHub release, which is what the
`curl | sh` installer downloads.

## Usage

1. `nebula`
2. Click **Attach** (or run `nebula-attach`) — this applies the Flatpak override
3. Launch Roblox through Sober and join any experience
4. The header shows **● attached** when the hook captures the Luau state
5. Type/paste a script and press **Execute** (F5)

## Files

| Path | Purpose |
|---|---|
| `~/.nebula/queue/exec.lua` | Script queue (GUI → hook) |
| `~/.nebula/queue/log` | Hook → GUI console stream |
| `~/.nebula/queue/status` | `WAITING` / `ATTACHED` heartbeat |
| `~/.nebula/scripts/` | Your saved scripts |
| `~/.nebula/prefs.json` | UI preferences |

## Build from source

```sh
git clone <this repo> && cd nebula
cargo build --release
# artifacts:
#   target/release/nebula              (GUI)
#   target/release/libnebula_hook.so   (injected hook)
```

## Project layout

```
crates/
  nebula-core/   Sober detection, flatpak override logic, script queue
  nebula-hook/   cdylib injected into Sober (Luau state capture + executor)
  nebula/        eframe/egui desktop app
tests/           fake Luau runtime + e2e pipeline test (no Sober needed)
install.sh       distro-aware one-line installer (GitHub-hosted)
nebula-attach    headless attach helper
pack.sh          builds the release tarball
.github/         release workflow (tag v* → attaches tarball to GitHub release)
examples/        sample scripts
```

## Safety & disclaimer

Executing arbitrary scripts in a live game can violate Roblox's ToS and get
accounts moderated. Nebula is an educational RE project — use at your own risk.
Not affiliated with Roblox or VinegarHQ.

## License

MIT
