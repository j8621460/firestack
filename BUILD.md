# Building firestack (this fork)

This branch is **pinned to the pre-`n2` API**. Upstream `n2` rewrote the surface
firestack exports to Java/Kotlin: it removed the `Gostr` / `Gobyte` wrappers,
changed `OnQuery` from 3 arguments to 4, and moved DNS handling into a new
`TunDnsManager`. Consumers written against the older API do not compile against
`n2`.

What this branch keeps:

| symbol | where | note |
|---|---|---|
| `Gostr`, `Gostr2` | `intra/backend/core_boxes.go` | string box; removed in `n2` |
| `Gobyte` | `intra/backend/core_boxes.go` | byte-slice box; removed in `n2` |
| `OnQuery(who, uid, domain *Gostr, qtyp int)` | `intra/backend/dnsx_listener.go` | 3-arg form |
| `AnnounceUDP` | `intra/protect/xdial.go` | SOCKS5 UDP ASSOCIATE |

---

## What gets built

`gomobile bind` compiles the Go sources into an Android library:

| output | contents |
|---|---|
| `firestack.aar` | stripped — use for release builds |
| `firestack-debug.aar` | with debug symbols |
| `build/intra/tun2socks-sources.jar` | sources, for IDE navigation |

`make-aar` renames `build/intra/tun2socks.aar` to `firestack.aar` at the end;
both names refer to the same artifact.

## Requirements

| tool | version | why |
|---|---|---|
| Go | **1.26+** | `go.mod` declares `go 1.26`; older toolchains refuse the module |
| Android SDK platform | **36** | gomobile fails without a platform installed |
| Android build-tools | **36.0.0** | |
| Android NDK | **28.2.13676358** | cgo cross-compilation |
| JDK | 17+ | |

The NDK version matters. `make-aar` lets gomobile pick the newest NDK it finds
under `$ANDROID_HOME/ndk`, so leaving it unpinned means the output silently
changes whenever the machine or CI image updates. Pin it.

## Build in CI

Push a tag and the `📦 Release AAR` workflow builds and publishes the aars as
release assets:

```bash
git tag aar-2026.08.20
git push origin aar-2026.08.20
```

Or run it from the Actions tab (**Release AAR → Run workflow**) and give it a
tag name — useful for a one-off build without tagging the branch first.

## Build locally

```bash
export ANDROID_HOME="$HOME/Android/Sdk"
export NDKVER="28.2.13676358"
export SDKVER="36"

"$ANDROID_HOME"/cmdline-tools/latest/bin/sdkmanager \
    "platforms;android-${SDKVER}" \
    "build-tools;${SDKVER}.0.0" \
    "ndk;${NDKVER}"

# "nogo"  -> use the Go already on PATH
# "debug" -> also emit firestack-debug.aar
./make-aar nogo debug
```

Drop the `nogo` argument and `make-aar` downloads Go 1.26.0 from `go.dev` itself
and verifies its sha256 — handy on a machine with no Go installed, or when you
want the exact toolchain CI uses.

Underneath, `make-aar` runs:

```bash
make clean && make intra && make intradebug
```

so `make intra` alone is enough if you only want the stripped aar.

## Consuming it

Put the aar in your app and reference the file directly — no JitPack, no
network resolution at build time:

```groovy
// app/libs/firestack.aar
dependencies {
    implementation files('libs/firestack.aar')
}
```

Direct file dependency is deliberate here. JitPack builds this repo per-commit
and rate-limits (HTTP 429) under load, which fails the consuming build during
dependency resolution rather than at compile time — a confusing failure that
looks like a code problem. Publishing to Maven Central is not an option for a
fork either, since that coordinate belongs to upstream.

## Verifying a build

```bash
unzip -l firestack.aar | grep classes.jar   # must exist
sha256sum firestack.aar
```

An aar without `classes.jar` is a shell with no bytecode — gomobile can emit one
when the bind step fails but the packaging step does not. The release workflow
checks for it, so a broken artifact fails CI instead of reaching a consumer.

## Troubleshooting

**`gomobile: failed to find android SDK platform`** — the platform is missing.
Install `platforms;android-36`.

**`no NDK found` / wrong ABI** — `$ANDROID_HOME/ndk/$NDKVER` does not exist.
`make-aar` runs `ls` on that path and fails loudly on purpose.

**`go: go.mod requires go >= 1.26`** — the toolchain is too old. Run `go version`;
in CI, check `actions/setup-go` resolved `>=1.26` rather than a cached older one.

**Consumer fails with `Unresolved reference: Gostr`** — the app is resolving
firestack from somewhere else (JitPack or Maven Central both serve the `n2` API).
Check which coordinate the app's `build.gradle` actually uses.
