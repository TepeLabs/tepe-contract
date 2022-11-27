# Tepe Smart contract for the Secret network 

We started with the [SNIP 721 reference implementation](https://github.com/baedrik/snip721-reference-impl) and stripped away a lot of features that were non-essential for our purpose before adding the Tepe functionality.

The interesting stuff can be found in `src/contract.rs`.

To upload an identical version of contract `15064` you would just run `cargo build` and then [optimize the contract for upload](https://hub.docker.com/r/enigmampc/secret-contract-optimizer).
