# hsec-core

`hesc-core` aims to support [Haskell advisories database](https://github.com/haskell/security-advisories).

## Building

We aim to support both regular cabal-based and nix-based builds.

## Testing

Run (and auto update) the golden test:

```ShellSession
cabal test -O0 --test-show-details=direct --test-option=--accept
```
