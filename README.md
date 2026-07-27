# GhosterDex Wallet Core

The cryptographic core of the [GhosterDex](https://ghosterdex.com) wallet: key
generation, derivation, and the sealing that keeps a recovery phrase on the
device it was created on.

Published so the security claims can be checked rather than believed. This is
the key handling and its tests, not the whole application: what is in and out
of scope is listed in full below, before you read anything else into it.

```
83 instrumented tests, run against a real Android Keystore.
```

---

## Why this repo exists

GhosterDex tells its users that their recovery phrase is generated on their
phone, sealed by hardware, and never sent anywhere. Nobody can verify a
sentence like that against a compiled binary.

So the code that would have to be lying is here, along with the tests that
demonstrate otherwise. Clone it, read it, run them.

## What is here, and what is not

**Here:** everything that touches key material.

| | |
| --- | --- |
| `Bip39`, `TonMnemonic`, `RecoveryPhrase` | phrase generation and validation |
| `Slip10`, `TonKey`, `TonDerivation` | Ed25519 derivation, both TON schemes |
| `SecureVault` | Keystore sealing, the app-lock policies, key rotation |
| `TonProofSigner`, `TonConnectSigner` | the two signature envelopes |
| `TonCell`, `Base58`, `WalletKey` | address formats and serialisation |
| `Secrets` | wiping key material from memory |
| `WalletRegistry`, `WalletMeta` | which wallet is which, and whether it is backed up |

**Not here:** the app itself. Interface, bridge, networking, trading, Gram
Zone, referrals. None of it handles keys, and none of it is needed to check the
claims above.

Publishing the core and keeping the application closed is a deliberate split,
and it has a limit worth stating plainly rather than leaving for someone to
discover. Read [Verifying the claims](#verifying-the-claims) before deciding
what this repo does and does not prove.

## Running the tests

Requires a connected device or emulator, since the whole point is a **real
Android Keystore**. A Keystore cannot be mocked into telling the truth.

```bash
./gradlew :core:connectedDebugAndroidTest
```

Nothing else to configure. What runs:

- **`CryptoVectorsTest`** checks BIP39 and SLIP-0010 against the published test
  vectors, so derivation is standard rather than homegrown.
- **`TonVectorsTest`** checks TON mnemonic, key derivation and address
  computation against the output of `@ton/crypto` and `@ton/ton`, so agreement
  is with the ecosystem rather than with itself.
- **`SecureVaultTest`** seals and unseals through a real Keystore key.
- **`RekeyTest`** changes the app lock on a sealed wallet and shows the address
  and phrase survive, and that an interrupted rotation leaves the wallet whole
  on one side or the other rather than in between.
- **`HardeningTest`** covers the refusals: tampered ciphertext, a wrong key, a
  reused slot.
- **`SecurityPolicyTest`** covers the three lock choices.
- **`BiometricRoundTripTest`** seals and unseals through a
  CryptoObject-bound `BiometricPrompt`. It **skips** unless the device has an
  enrolled fingerprint and something is feeding the sensor, so a green run on a
  bare emulator is not evidence the biometric path works. To actually run it:

  ```bash
  while ($true) { adb emu finger touch 1; Start-Sleep -Milliseconds 500 }
  ```

## The design, in short

**Keys are generated on the device and never leave it.** The phrase is sealed
with AES-256-GCM under a key that lives in the Android Keystore, in StrongBox
where the hardware provides it. The Keystore key is not extractable; nothing in
this library asks for it and nothing could obtain it.

**The lock is enforced by the OS, not by the app.** Choosing fingerprint sets
`setUserAuthenticationRequired` with a zero timeout, which forces every single
use through a `BiometricPrompt` bound to that operation's `Cipher`. Skipping
the check is not a code path an attacker can find, because the check is the
Keystore's, not ours. `AUTH_BIOMETRIC_STRONG` excludes the convenience
biometrics that miss Android's spoof thresholds.

**Enrolling a new fingerprint destroys the key.** Otherwise anyone who could
add a finger to an unlocked phone could sign with it.

**The key is unusable while the phone is locked.** `setUnlockedDeviceRequired`,
whatever policy the wallet was created with. It is the only protection that
still applies to a wallet whose owner chose no lock at all.

**Changing a lock does not move the phrase.** `SecureVault` rotates to a new
Keystore key, re-seals, commits once, and only then deletes the old key. An
interruption anywhere in that sequence leaves the wallet entirely on the old
key or entirely on the new one.

**Memory is wiped.** Phrases are handled as `CharArray` and `ByteArray` and
cleared after use. A `String` cannot be erased, so key material is never one.

## Verifying the claims

What this repo lets you check for yourself:

- derivation matches the published vectors, so an address is reproducible in
  any other wallet from the same phrase;
- the Keystore key is generated non-extractable, with the authentication
  parameters described above;
- sealing and unsealing round-trip, and refuse when they should;
- no function here returns a key, a seed or a phrase to a caller that did not
  already unlock the vault.

What it does not let you check: the app shell is closed, so you cannot confirm
from this repo alone that nothing in the shipped app exports key material after
unlocking it. In the app that boundary is a bridge with no method returning key
material, but you are taking that on trust here.

We would rather say so than let an "open source" badge imply more than it does.

## Reproducing a build

The published APK is built from this core plus the closed shell, signed with
GhosterDex's release key. You can confirm an APK you downloaded is the one we
signed:

```bash
apksigner verify --print-certs GhosterDex.apk
```

```
Signer #1 certificate SHA-256 digest:
a6263e9fc27c31ad5ce362656fc368926e1c98aa3e00bc134d3f61d850701e7d
```

That fingerprint is also published at
[`/.well-known/assetlinks.json`](https://ghosterdex.com/.well-known/assetlinks.json),
where Android reads it to verify app links, so it can be cross-checked without
trusting this file.

## Download

Releases here carry the signed APK. [ghosterdex.com](https://ghosterdex.com)
links to the same file.

## Reporting a vulnerability

Please do not open a public issue for anything exploitable. Email
`security@ghosterdex.com` and give us a chance to ship a fix first.

## Where to find us

- Channel: [t.me/ghosterdexx](https://t.me/ghosterdexx)
- X: [@GhosterDex](https://x.com/GhosterDex)
- Mini app: [t.me/GhosterdexBot](https://t.me/GhosterdexBot?startapp)
- Site: [ghosterdex.com](https://ghosterdex.com)

## Licence

MIT. See [LICENSE](LICENSE). Using this core does not give you any rights over
the GhosterDex application, its name, or its branding.
