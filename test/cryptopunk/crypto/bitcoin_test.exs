defmodule Cryptopunk.Crypto.BitcoinTest do
  use ExUnit.Case

  alias Cryptopunk.Crypto.Bitcoin
  alias Cryptopunk.Derivation
  alias Cryptopunk.Derivation.Path
  alias Cryptopunk.Key

  test "generates address from extended public key" do
    public_key =
      "xpub6C35qtG2zHpXwVKjpEmTjam5igvoQh2bYkPNdYrCekv44W3ioNi8DJ7zAXTuWgYCbm57ZZRhgiwC56dCYvzfur7pxwKQhcgqga7fafdeH4q"

    key = Key.deserialize(public_key)

    assert "1G2WGDknNjKDArLZTxwvbF3ftD8dR6o5nS" == Bitcoin.address(key, :mainnet)
  end

  test "generates the first address for BIP44 path" do
    {:ok, path} = Path.parse("M/44'/0'/0'/0/0")

    extended_private_key =
      "xprv9s21ZrQH143K4RdNK1f51Rdeu4XRG8q2cgzeh7ejtzgYpdZcHpNb1MJ2DdBa4iX6NVoZZajsC4gr26mLFaHGBrrtvGkxwhGh6ng8HVZRSeV"

    master_key = Key.deserialize(extended_private_key)
    derived_public_key = Derivation.derive(master_key, path)

    assert "15HJfZhj5V9qQeyvFxPxMWNzRbcZpFUAaA" == Bitcoin.address(derived_public_key, :mainnet)
  end
end
