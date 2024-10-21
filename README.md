# Cryptopunk

  Hierarchical deterministic wallet. It has the following features:

  - Generate mnemonic
  - Generate seed from mnemonic
  - Generate master keys from seed
  - Derive private and public keys from the master key
  - Various utility functions to work with derivation path, keys, crypto addresses

## Installation

The package can be installed by adding `cryptopunk` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:cryptopunk, "~> 0.7.6"}
  ]
end
```

## Usage

The docs can be found at [https://hexdocs.pm/cryptopunk](https://hexdocs.pm/cryptopunk).

### Basic usage:

Create mnemonic:

```elixir
iex> Cryptopunk.create_mnemonic()

"above ability arm album essay kite card believe antique type express word piece unusual describe toilet subway reward slab exhaust leave found debate measure"

```

Generate seed:

```elixir
iex> Cryptopunk.create_seed("above ability arm album essay kite card believe antique type express word piece unusual describe toilet subway reward slab exhaust leave found debate measure")

<<238, 144, 139, 163, 73, 169, 105, 114, 35, 246, 61, 250, 202, 232, 15, 129,
  61, 56, 96, 229, 32, 54, 17, 217, 246, 124, 15, 34, 84, 146, 86, 54, 86, 53,
  24, 51, 185, 230, 68, 57, 38, 60, 134, 92, 142, 154, 112, 233, 81, 195, 241,
  217, 184, 90, 142, 157, 139, 170, 54, 217, 126, 103, 222, 36>>
```

Create master key from seed:

```elixir
iex> seed = <<238, 144, 139, 163, 73, 169, 105, 114, 35, 246, 61, 250, 202, 232, 15, 129,
  61, 56, 96, 229, 32, 54, 17, 217, 246, 124, 15, 34, 84, 146, 86, 54, 86, 53,
  24, 51, 185, 230, 68, 57, 38, 60, 134, 92, 142, 154, 112, 233, 81, 195, 241,
  217, 184, 90, 142, 157, 139, 170, 54, 217, 126, 103, 222, 36>>

iex> Cryptopunk.master_key_from_seed(seed)
%Cryptopunk.Key{
  chain_code: <<77, 200, 226, 224, 92, 36, 49, 31, 19, 168, 206, 8, 212, 142,
    54, 191, 170, 82, 7, 37, 208, 240, 11, 182, 255, 251, 254, 150, 242, 28,
    201, 174>>,
  depth: 0,
  index: 0,
  key: <<89, 119, 58, 88, 77, 111, 18, 206, 249, 68, 10, 227, 209, 205, 174, 81,
    183, 26, 194, 195, 243, 249, 218, 32, 142, 80, 252, 217, 90, 178, 132,
    162>>,
  parent_fingerprint: <<0, 0, 0, 0>>,
  type: :private
}
```

Derive key from master key:

```elixir
iex> {:ok, path} = Cryptopunk.parse_path("m / 44' / 0' / 0' / 0 / 0")

iex> key = Cryptopunk.master_key_from_seed(seed)
%Cryptopunk.Key{
  chain_code: <<77, 200, 226, 224, 92, 36, 49, 31, 19, 168, 206, 8, 212, 142,
    54, 191, 170, 82, 7, 37, 208, 240, 11, 182, 255, 251, 254, 150, 242, 28,
    201, 174>>,
  depth: 0,
  index: 0,
  key: <<89, 119, 58, 88, 77, 111, 18, 206, 249, 68, 10, 227, 209, 205, 174, 81,
    183, 26, 194, 195, 243, 249, 218, 32, 142, 80, 252, 217, 90, 178, 132,
    162>>,
  parent_fingerprint: <<0, 0, 0, 0>>,
  type: :private
}

iex> Cryptopunk.derive_key(key path)
%Cryptopunk.Key{}

```

## Contributing

1. [Fork it!](https://github.com/ayrat555/ex_secp256k1)
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create new Pull Request
