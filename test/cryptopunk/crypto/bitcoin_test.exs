defmodule Cryptopunk.Crypto.BitcoinTest do
  use ExUnit.Case

  alias Cryptopunk.Crypto.Bitcoin
  alias Cryptopunk.Derivation
  alias Cryptopunk.Derivation.Path
  alias Cryptopunk.Key

  describe "legacy_address/2" do
    test "generates legacy_address from extended public key" do
      public_key =
        "xpub6C35qtG2zHpXwVKjpEmTjam5igvoQh2bYkPNdYrCekv44W3ioNi8DJ7zAXTuWgYCbm57ZZRhgiwC56dCYvzfur7pxwKQhcgqga7fafdeH4q"

      key = Key.deserialize(public_key)

      assert "1G2WGDknNjKDArLZTxwvbF3ftD8dR6o5nS" == Bitcoin.legacy_address(key, :mainnet)
    end

    test "generates the first legacy_address for BIP44 path" do
      {:ok, path} = Path.parse("M/44'/0'/0'/0/0")

      extended_private_key =
        "xprv9s21ZrQH143K4RdNK1f51Rdeu4XRG8q2cgzeh7ejtzgYpdZcHpNb1MJ2DdBa4iX6NVoZZajsC4gr26mLFaHGBrrtvGkxwhGh6ng8HVZRSeV"

      master_key = Key.deserialize(extended_private_key)
      derived_public_key = Derivation.derive(master_key, path)

      assert "15HJfZhj5V9qQeyvFxPxMWNzRbcZpFUAaA" ==
               Bitcoin.legacy_address(derived_public_key, :mainnet)
    end
  end

  describe "p2sh_p2wpkh_address/2" do
    setup do
      mnemonic =
        "balance focus there ocean traffic verb device piece ethics anchor chief make useful never cable"

      master_key =
        mnemonic
        |> Cryptopunk.create_seed()
        |> Cryptopunk.master_key_from_seed()

      %{master_key: master_key}
    end

    test "generates p2sh_p2wpkh mainnet address", %{master_key: master_key} do
      {:ok, path} = Cryptopunk.parse_path("m/49'/0'/0'/0/0")

      key = Cryptopunk.derive_key(master_key, path)

      assert "3C6oMpgWjdGrnAxZbjsiW3L7Vcorc4KbqV" == Bitcoin.p2sh_p2wpkh_address(key, :mainnet)
    end

    test "generates p2sh_p2wpkh testnet address", %{master_key: master_key} do
      {:ok, path} = Cryptopunk.parse_path("m/49'/1'/0'/0/0")

      key = Cryptopunk.derive_key(master_key, path)

      assert "2MtEWsJk8NDJBUhgVJuufMwcdRbjdYEgBQ4" == Bitcoin.p2sh_p2wpkh_address(key, :testnet)
    end
  end

  describe "bech32_address/3" do
    setup do
      mnemonic =
        "royal blossom shell cram arrow skirt panda review multiply jungle elevator fly injury network fold"

      master_key =
        mnemonic
        |> Cryptopunk.create_seed()
        |> Cryptopunk.master_key_from_seed()

      %{master_key: master_key}
    end

    test "generates bech32 mainnet address", %{master_key: master_key} do
      {:ok, path} = Cryptopunk.parse_path("m/84'/0'/0'/0/0")

      key = Cryptopunk.derive_key(master_key, path)

      assert "bc1qnv5fzufzf3l4uj9ey95w6zw32nevwjxn9497vk" ==
               Bitcoin.bech32_address(key, :mainnet, version: 1)
    end
  end
end
