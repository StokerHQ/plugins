# StokerHQ plugin registry

The public registry of plugins for Stoker: hook plugins a game loads, mods, integrations and server extensions, each
version signed by its publisher and listed here. A Stoker instance subscribes to this registry by its URL and key, finds
plugins in it, checks them, and installs a version once an administrator approves it. The format is
[plugins v1](https://schemas.stokerhq.app/) (StokerHQ/schemas, "Plugin registries").

This repository is the **index** only. The files are release assets on each plugin's own repository; an entry names
them by URL and hash.

| Path | What it is |
|---|---|
| `registry.yaml` | This registry: its key, its publishers and the key prefixes each may publish under, its policy |
| `plugins/<key>/plugin.yaml` | One plugin |
| `plugins/<key>/<version>.yaml` | One version: its release, its source commit, every file by URL, size, SHA-256 and BLAKE3, and the publisher's signature |
| `index/v1/` (published, not committed) | The compiled index an instance reads, and `timestamp.json` with its signature |

**Policy.** This registry refuses `unpacker` plugins and integrations that answer a store's ownership check
(`ubisoftConnect`, `epicOnlineServices`).

## Publishing a version

`stoker-registry` is the registry tool, a .NET tool released with the Stoker plugin SDK (StokerHQ/plugin-sdk). The keys
are made once; everything after is per version.

```powershell
dotnet tool install -g StokerHQ.PluginRegistry.Tool      # .NET 10 SDK
```

1. **Once: the two keys.** Keep both private keys and their passphrases out of every repository.

   ```powershell
   stoker-registry keygen --out registry.pem      # the registry's key: signs the compiled index
   stoker-registry keygen --out publisher.pem     # the stokerhq publisher's key: signs each version
   ```

   Put the printed public keys into `registry.yaml` (`key`, and `publishers[stokerhq].publicKey`), replacing the
   placeholders.

2. **Release the plugin** on its own repository: tag `v<version>` (or `<key>/<version>` in a repository of several
   plugins), with the built files attached as assets.

3. **Write the entry from the release**, signed:

   ```powershell
   stoker-registry version --key publisher.pem --publisher stokerhq --plugin app.stokerhq.peacock --version 1.3.0 --kind hook `
     --repository https://github.com/StokerHQ/peacock-plugin --tag v1.3.0 --commit <the tagged commit> `
     --file windows x64 peacock-windows-x64.dll https://github.com/StokerHQ/peacock-plugin/releases/download/v1.3.0/peacock-windows-x64.dll `
     --out plugins/app.stokerhq.peacock
   ```

   For a hook plugin it reads each file's manifest, refuses a file of another plugin, version, OS or architecture,
   and writes `abi`, `hosts`, `manifestSha256` and `config` from it. Another kind's own fields are added by hand; the
   signature does not cover them.

4. **Check it against the release** and open a pull request:

   ```powershell
   stoker-registry check . --download    # for a hook, also compares the file's manifest with the entry
   ```

5. **After the merge, compile and sign the index** (the registry's key stays on the operator's machine):

   ```powershell
   stoker-registry compile . --out site --previous site
   stoker-registry sign site --key registry.pem
   stoker-registry verify-index site --key registry.yaml
   ```

   Publishing `site/index/v1/` (with `timestamp.json.sig`) is what makes the new index live.

6. **Publish the website** from the gh-pages worktree (made once with `git worktree add ../plugins-gh-pages gh-pages`):

   ```powershell
   ./scripts/Publish-Site.ps1 -Worktree ../plugins-gh-pages -Push
   ```

   It verifies the index, builds the site and replaces the branch's content in one commit.

## The website

[plugins.stokerhq.app](https://plugins.stokerhq.app) is the explorer in `pages/`: a static page that reads the same
signed index an instance reads, checks the index's signature, its pin and its expiry, and each version's publisher
signature in the browser, and searches the index in memory. `scripts/Build-Site.ps1 -Out <new folder>` assembles it
with the index for a local look (`py -m http.server --directory <folder>`); the registry's name, title, URL and key
are filled into `index.html` from `registry.yaml`. `pages/vendor/fzstd.mjs` is fzstd 0.1.1 (MIT), unmodified,
which decompresses the index.

## Checks

Pull requests are checked by CI with the schemas repository's validator. It checks the format, the namespaces and the
policy; the signatures and the files' hashes are what `stoker-registry check --download` checks.
