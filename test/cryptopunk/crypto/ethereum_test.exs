defmodule Cryptopunk.Crypto.EthereumTest do
  use ExUnit.Case

  alias Cryptopunk.Crypto.Ethereum
  alias Cryptopunk.DerivationPath
  alias Cryptopunk.Key
  alias Cryptopunk.Keys
  alias Cryptopunk.Seed

  setup do
    master_key =
      "nurse grid sister metal flock choice system control about mountain sister rapid hundred render shed chicken print cover tape sister zero bronze tattoo stairs"
      |> Seed.create()
      |> Key.master_key()

    path = "m/44'/60'/0'/0"

    expected = %{
      0 => "0x73bb50c828fd325c011d740fde78d02528826156",
      1 => "0x66dc6301a2affad6087b9600d192f22f0de76b4c"
    }

    %{master_key: master_key, expected: expected, path: path}
  end

  test "correct wallet generation", %{master_key: master_key, path: path, expected: expected} do
    Enum.map(0..1, fn n ->
      {:ok, parsed_path} = DerivationPath.parse(path <> "/#{n}")

      derived_key = Keys.derive(master_key, parsed_path)

      assert expected[n] == Ethereum.address(derived_key)
    end)
  end
end
