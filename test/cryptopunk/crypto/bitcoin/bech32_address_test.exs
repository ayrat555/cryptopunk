defmodule Cryptopunk.Crypto.Bitcoin.Bech32AddressTest do
  use ExUnit.Case

  alias Cryptopunk.Crypto.Bitcoin.Bech32Address

  describe "validate/1" do
    test "validates a taproot address (mainnet)" do
      assert {:ok, %{network: :mainnet, type: :p2tr}} =
               Bech32Address.validate("bc1pmzfrwwndsqmk5yh69yjr5lfgfg4ev8c0tsc06e")
    end

    test "validates a p2wpkh address (mainnet)" do
      assert {:ok, %{network: :mainnet, type: :p2wpkh}} =
               Bech32Address.validate("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq")
    end

    test "validates a p2sh (mainnet)" do
      {:ok, %{network: :mainnet, type: :p2wsh}} =
        Bech32Address.validate("bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3")
    end
  end
end
