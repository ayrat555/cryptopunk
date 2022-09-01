defmodule Cryptopunk.Key.WIFTest do
  use ExUnit.Case

  alias Cryptopunk.Key
  alias Cryptopunk.Key.WIF

  describe "encode/2" do
    test "encodes key on mainnet with compression" do
      private_key =
        <<50, 8, 92, 222, 223, 155, 132, 50, 53, 227, 114, 79, 88, 11, 248, 24, 239, 76, 236, 39,
          195, 198, 112, 133, 224, 41, 65, 138, 91, 47, 111, 43>>

      params = [network: :mainnet, compression: true]

      assert "Kxty66SRDbbSYUWL76fUaSuBfBuNDj7SCvc6m5ywpEBqq2tBh1PG" ==
               WIF.encode(private_key, params)
    end

    test "encodes key on testnet without compression" do
      private_key = %Key{
        key:
          <<50, 8, 92, 222, 223, 155, 132, 50, 53, 227, 114, 79, 88, 11, 248, 24, 239, 76, 236,
            39, 195, 198, 112, 133, 224, 41, 65, 138, 91, 47, 111, 43>>,
        type: :private
      }

      params = [network: :testnet]

      assert "cPFxZ1SGefHhhuybVWUbwmQFHRCmtBD8GxkZsWSTKLqr5muDxfBL" ==
               WIF.encode(private_key, params)
    end
  end

  describe "decode/2" do
    test "decodes key on mainnet with compression" do
      assert <<50, 8, 92, 222, 223, 155, 132, 50, 53, 227, 114, 79, 88, 11, 248, 24, 239, 76, 236,
               39, 195, 198, 112, 133, 224, 41, 65, 138, 91, 47, 111,
               43>> ==
               WIF.decode(
                 "Kxty66SRDbbSYUWL76fUaSuBfBuNDj7SCvc6m5ywpEBqq2tBh1PG",
                 network: :mainnet,
                 compression: true
               )
    end

    test "decodes key on testnet without compression" do
      assert <<50, 8, 92, 222, 223, 155, 132, 50, 53, 227, 114, 79, 88, 11, 248, 24, 239, 76, 236,
               39, 195, 198, 112, 133, 224, 41, 65, 138, 91, 47, 111,
               43>> ==
               WIF.decode(
                 "cPFxZ1SGefHhhuybVWUbwmQFHRCmtBD8GxkZsWSTKLqr5muDxfBL",
                 network: :testnet
               )
    end
  end
end
