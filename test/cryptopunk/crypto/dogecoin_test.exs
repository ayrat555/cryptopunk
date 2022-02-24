defmodule Cryptopunk.Crypto.DogecoinTest do
  use ExUnit.Case

  alias Cryptopunk.Crypto.Dogecoin

  doctest Dogecoin

  setup do
    mnemonic =
      "hamster citizen citizen response rival want climb comfort bulk exist skill receive shrimp meat lumber"

    master_key =
      mnemonic
      |> Cryptopunk.create_seed()
      |> Cryptopunk.master_key_from_seed()

    %{master_key: master_key}
  end

  test "generates testnet dogecoin address", %{master_key: master_key} do
    {:ok, path} = Cryptopunk.parse_path("m/44'/1'/0'/0/0")
    key = Cryptopunk.derive_key(master_key, path)

    address = Dogecoin.address(key, :testnet)

    assert "nhA8G4Ds2nam712vnLiXitLAyLhLHhL9M6" == address
  end

  test "generates mainnet dogecoin address", %{master_key: master_key} do
    {:ok, path} = Cryptopunk.parse_path("m/44'/3'/0'/0/0")
    key = Cryptopunk.derive_key(master_key, path)

    address = Dogecoin.address(key, :mainnet)

    assert "DPiwFnkrUPGfQ2Uk9jsAVJMuN3RV9t8CMz" == address
  end
end
