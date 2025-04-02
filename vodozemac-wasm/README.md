# vodozemac Javascript bindings

```diff 
- !! non official vodozemac-js binding !!
```

The [original megolm library](https://gitlab.matrix.org/matrix-org/olm/blob/master/docs/megolm.md) from matrix was deprecated and replaced with [vodozemac](https://github.com/matrix-org/vodozemac),
an equivalent rust implemnentation of the Olm/Megolm protocol.

This packages provides vodozemac JS bindings using rust-wasm compilation.

This is a fork from the original [vodozemac-bindings](https://github.com/matrix-org/vodozemac-bindings) repo which is no longer maintained.

## install

```shell
npm i vodozemac-wasm-bindings
```

## Example usage

- [1-to-1 Olm Session](https://github.com/Mekacher-Anis/vodozemac-wasm-bindings/blob/main/javascript/examples/1-to-1-olm.ts)
- [Megolm group chat](https://github.com/Mekacher-Anis/vodozemac-wasm-bindings/blob/main/javascript/examples/group-chat.ts)