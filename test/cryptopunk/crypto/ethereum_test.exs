defmodule Cryptopunk.Crypto.EthereumTest do
  use ExUnit.Case

  alias Cryptopunk.Crypto.Ethereum
  alias Cryptopunk.Derivation
  alias Cryptopunk.Derivation.Path
  alias Cryptopunk.Key
  alias Cryptopunk.Seed

  doctest Ethereum

  setup_all do
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

  describe "address/1" do
    test "correct wallet generation", %{master_key: master_key, path: path, expected: expected} do
      Enum.map(0..1, fn n ->
        {:ok, parsed_path} = Path.parse(path <> "/#{n}")

        derived_key = Derivation.derive(master_key, parsed_path)

        assert expected[n] == Ethereum.address(derived_key)
      end)
    end
  end

  describe "valid?/1" do
    test "validates random addresses", %{expected: expected} do
      Enum.each(expected, fn {_, address} ->
        assert Ethereum.valid?(address)
      end)
    end

    test "validates valid addresses" do
      # sample address values takem from https://github.com/ChainSafe/web3.js/blob/5d027191c5cb7ffbcd44083528bdab19b4e14744/test/utils.isAddress.js

      assert Ethereum.valid?("0xc6d9d2cd449a754c494264e1809c50e34d64562b")
      assert Ethereum.valid?("c6d9d2cd449a754c494264e1809c50e34d64562b")
      assert Ethereum.valid?("0xE247A45c287191d435A8a5D72A7C8dc030451E9F")
      assert Ethereum.valid?("0xe247a45c287191d435a8a5d72a7c8dc030451e9f")
      assert Ethereum.valid?("0xE247A45C287191D435A8A5D72A7C8DC030451E9F")
      assert Ethereum.valid?("0XE247A45C287191D435A8A5D72A7C8DC030451E9F")
    end

    test "invalidates addresss" do
      refute Ethereum.valid?("0x5AAEB6053f3e94c9b9a09f33669435e7ef1beaed")
      refute Ethereum.valid?("0xE247a45c287191d435A8a5D72A7C8dc030451E9F")
      refute Ethereum.valid?("myaddress")
    end
  end
end
