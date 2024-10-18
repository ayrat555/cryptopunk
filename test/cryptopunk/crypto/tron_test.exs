defmodule Cryptopunk.Crypto.TronTest do
  use ExUnit.Case

  alias Cryptopunk.Crypto.Tron
  alias Cryptopunk.Key

  doctest Tron

  test "generates the same address from public and private keys" do
    private_key = %Cryptopunk.Key{
      chain_code:
        <<153, 249, 145, 92, 65, 77, 50, 249, 120, 90, 178, 30, 41, 27, 73, 128, 74, 201, 91, 250,
          143, 238, 129, 247, 115, 87, 161, 107, 123, 63, 84, 243>>,
      key:
        <<50, 8, 92, 222, 223, 155, 132, 50, 53, 227, 114, 79, 88, 11, 248, 24, 239, 76, 236, 39,
          195, 198, 112, 133, 224, 41, 65, 138, 91, 47, 111, 43>>,
      type: :private,
      depth: 0,
      parent_fingerprint: <<0, 0, 0, 0>>,
      index: 0
    }

    public_key = Key.public_from_private(private_key)

    address_from_private_key = Tron.address(private_key)
    address_from_public_key = Tron.address(public_key)

    assert address_from_private_key == address_from_public_key
    assert "TJmuGjyJVmbPVyxuVsS9G2Uio5aEWvWLtb" == address_from_private_key
  end

  test "generates correct mainnet addresses from derivation path" do
    mnemonic =
      "gospel bitter ladder chimney critic glory decorate exist build rescue phrase good dust harbor tourist"

    seed = Cryptopunk.create_seed(mnemonic)
    master_key = Cryptopunk.master_key_from_seed(seed)
    base_path = "m/44'/195'/0'/0"

    expected_addresses = %{
      0 => "TLWMdArGeBCE3ktiu165w7Tiu2C2JEnW7p",
      1 => "TQ79zY3LC9bGAD9htj9mz8q9wkmKzpgCN3",
      2 => "TUYAGCna6UQZ7ogLCrQ3uz33fTsez9hKpo",
      3 => "TVoJtzDWT57sHJa9gy4q6CpMnDngDze3Kd",
      4 => "TELVvau4r1TkeWfZBYHPmmHCEdSv5PBzwZ",
      5 => "TLaybyfiyhDrXNwVf1P57bTxxksadEvmGZ"
    }

    Enum.each(expected_addresses, fn {idx, expected_address} ->
      {:ok, path} = Cryptopunk.parse_path("#{base_path}/#{idx}")

      key = Cryptopunk.derive_key(master_key, path)

      assert expected_address == Tron.address(key)
    end)
  end

  test "test address validation (valid addresses)" do
    expected_addresses = %{
      0 => "TLWMdArGeBCE3ktiu165w7Tiu2C2JEnW7p",
      1 => "TQ79zY3LC9bGAD9htj9mz8q9wkmKzpgCN3",
      2 => "TUYAGCna6UQZ7ogLCrQ3uz33fTsez9hKpo",
      3 => "TVoJtzDWT57sHJa9gy4q6CpMnDngDze3Kd",
      4 => "TELVvau4r1TkeWfZBYHPmmHCEdSv5PBzwZ",
      5 => "TLaybyfiyhDrXNwVf1P57bTxxksadEvmGZ"
    }

    Enum.each(expected_addresses, fn {_idx, address} ->
      assert Tron.Validation.valid?(address)
      assert Tron.ChecksumEncoding.valid?(address)
    end)
  end

  test "test address validation (bad addresses)" do
    expected_addresses = %{
      0 => "TLWMdArGecCE3ktiu165w7Tiu2C2JEnW7p",
      1 => "TPepeAddress",
      2 => "TUYAGCna6UrZ7ogLCrf3uz33fTsez9hKpo"
    }

    Enum.each(expected_addresses, fn {_idx, address} ->
      refute Tron.Validation.valid?(address)
      refute Tron.ChecksumEncoding.valid?(address)
    end)
  end

  test "test address validation (valid addresses generated from mnemonic)" do
    mnemonic = Cryptopunk.create_mnemonic()

    seed = Cryptopunk.create_seed(mnemonic)
    master_key = Cryptopunk.master_key_from_seed(seed)
    base_path = "m/44'/195'/0'/0"

    Enum.each(1..5, fn idx ->
      {:ok, path} = Cryptopunk.parse_path("#{base_path}/#{idx}")
      key = Cryptopunk.derive_key(master_key, path)
      address = Tron.address(key)

      assert Tron.Validation.valid?(address)
      assert Tron.ChecksumEncoding.valid?(address)
    end)
  end
end
