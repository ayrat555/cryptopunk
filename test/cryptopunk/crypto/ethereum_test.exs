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

  describe "checksum_encode/1" do
    test "encodes addresses" do
      # All caps
      assert {:ok, "0x52908400098527886E0F7030069857D2E4169EE7"} ==
               Ethereum.checksum_encode("0x52908400098527886e0f7030069857d2e4169ee7")

      assert {:ok, "0x8617E340B3D01FA5F11F306F4090FD50E238070D"} ==
               Ethereum.checksum_encode("0x8617e340b3d01fa5f11f306f4090fd50e238070d")

      # All Lower
      assert {:ok, "0xde709f2102306220921060314715629080e2fb77"} ==
               Ethereum.checksum_encode("0xde709f2102306220921060314715629080e2fb77")

      assert {:ok, "0x27b1fdb04752bbc536007a920d24acb045561c26"} ==
               Ethereum.checksum_encode("0x27b1fdb04752bbc536007a920d24acb045561c26")

      # Normal
      assert {:ok, "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"} ==
               Ethereum.checksum_encode("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed")

      assert {:ok, "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359"} ==
               Ethereum.checksum_encode("0xfb6916095ca1df60bb79ce92ce3ea74c37c5d359")

      assert {:ok, "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB"} ==
               Ethereum.checksum_encode("0xdbf03b407c01e7cd3cbea99509d93f8dddc8c6fb")

      assert {:ok, "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb"} ==
               Ethereum.checksum_encode("0xd1220a0cf47c7b9be7a2e6ba89f429762e7b9adb")
    end

    test "fails on unknown character" do
      assert {:error, {:unknown_char, "ь"}} ==
               Ethereum.checksum_encode("0x52908400098527886E0F7030069857D2E4169EЬ")
    end

    test "fails if address has a wrong length" do
      assert {:error, :invalid_address_length} ==
               Ethereum.checksum_encode("0x52908400098527886E0F7030069857D2E41")
    end
  end
end
