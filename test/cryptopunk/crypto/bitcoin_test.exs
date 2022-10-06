defmodule Cryptopunk.Crypto.BitcoinTest do
  use ExUnit.Case

  alias Cryptopunk.Crypto.Bitcoin
  alias Cryptopunk.Derivation
  alias Cryptopunk.Derivation.Path
  alias Cryptopunk.Key

  doctest Bitcoin

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

    test "generates address from uncompressed public key" do
      public_key = %Cryptopunk.Key{
        chain_code:
          <<184, 11, 206, 224, 102, 96, 47, 80, 46, 138, 85, 56, 176, 38, 61, 128, 29, 175, 239,
            140, 82, 86, 80, 48, 90, 182, 192, 180, 100, 69, 49, 128>>,
        depth: 5,
        index: 0,
        key:
          <<4, 24, 46, 89, 53, 195, 145, 241, 19, 7, 237, 101, 67, 103, 24, 237, 71, 59, 96, 213,
            38, 203, 90, 197, 19, 54, 100, 111, 138, 147, 230, 116, 172, 115, 191, 63, 16, 149,
            104, 132, 201, 171, 19, 104, 7, 197, 136, 141, 243, 217, 190, 97, 123, 94, 5, 135, 82,
            10, 195, 207, 205, 156, 48, 246, 39>>,
        parent_fingerprint: <<115, 62, 87, 238>>,
        type: :public
      }

      assert "18ejJd8nqhYbtY4Z6arYL21LetCS6fwbpM" ==
               Bitcoin.legacy_address(public_key, :mainnet, uncompressed: true)

      assert "moAgbgDmeiyrfeYAp9pv9wDfWso8yVYSjP" ==
               Bitcoin.legacy_address(public_key, :testnet, uncompressed: true)
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
               Bitcoin.bech32_address(key, :mainnet)
    end

    test "generates bech32 testnet address", %{master_key: master_key} do
      {:ok, path} = Cryptopunk.parse_path("m/84'/1'/0'/0/0")

      key = Cryptopunk.derive_key(master_key, path)

      assert "tb1qc89hn5kmwxl804yfqmd97st3trarqr24wvvjmy" ==
               Bitcoin.bech32_address(key, :testnet)
    end

    test "generates bech32 regtest address", %{master_key: master_key} do
      {:ok, path} = Cryptopunk.parse_path("m/84'/1'/0'/0/0")

      key = Cryptopunk.derive_key(master_key, path)

      assert "bcrt1qc89hn5kmwxl804yfqmd97st3trarqr24v94lvd" ==
               Bitcoin.bech32_address(key, :regtest)
    end
  end

  describe "validate/1" do
    test "validates a legacy address (testnet)" do
      assert {:ok, %{network: :testnet, type: :p2pkh}} =
               Bitcoin.validate("moAgbgDmeiyrfeYAp9pv9wDfWso8yVYSjP")
    end

    test "validates a legacy address (mainnet)" do
      assert {:ok, %{network: :mainnet, type: :p2pkh}} =
               Bitcoin.validate("12G4VanRFvwdtw2mQGXsbYvjDvUERuifmM")
    end

    test "validates a p2sh (testnet)" do
      assert {:ok, %{network: :testnet, type: :p2sh}} =
               Bitcoin.validate("2MxE9cWrNMwBUB4LMWkXHfNaJETaKP4Z8re")
    end

    test "validates a p2sh (mainnet)" do
      assert {:ok, %{network: :mainnet, type: :p2sh}} =
               Bitcoin.validate("3KRGxQ5Y3ge67HhGz56HkMhRQUtK4Bh1dq")
    end

    test "validates a segwit address (regtest)" do
      assert {:ok, %{network: :regtest, type: :p2wpkh}} =
               Bitcoin.validate("bcrt1qlwyzpu67l7s9gwv4gzuv4psypkxa4fx4ggs05g")
    end
  end
end
