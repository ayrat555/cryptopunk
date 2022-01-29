defmodule Cryptopunk.Crypto.DogecoinTest do
  use ExUnit.Case

  alias Cryptopunk.Crypto.Dogecoin
  alias Cryptopunk.Key

  setup do
    private_key =
      Key.new_master_private(
        key:
          <<219, 162, 11, 89, 4, 244, 221, 147, 87, 42, 73, 58, 253, 66, 20, 243, 17, 214, 97,
            139, 0, 207, 143, 248, 75, 234, 153, 110, 70, 156, 58, 123>>,
        chain_code:
          <<77, 200, 226, 224, 92, 36, 49, 31, 19, 168, 206, 8, 212, 142, 54, 191, 170, 82, 7, 37,
            208, 240, 11, 182, 255, 251, 254, 150, 242, 28, 201, 174>>
      )

    {:ok, %{private_key: private_key}}
  end

  test "generates testnet dogecoin address", %{private_key: private_key} do
    address = Dogecoin.address(private_key, :testnet)

    assert "nhjk8mSKqzNLcgtuLvPWBeRqjJ216uyV6b" == address
  end

  test "generates mainnet dogecoin address", %{private_key: private_key} do
    address = Dogecoin.address(private_key, :mainnet)

    assert "DJggQkhQv1ucjiKiK6k3wEqYVRdi4h261t" == address
  end
end
