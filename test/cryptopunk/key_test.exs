defmodule Cryptopunk.KeyTest do
  use ExUnit.Case

  alias Cryptopunk.Key

  describe "master_key/1" do
    test "calculates master private key from seed" do
      seed =
        <<98, 235, 236, 246, 19, 205, 197, 254, 187, 41, 62, 19, 189, 20, 24, 73, 206, 187, 198,
          83, 160, 138, 77, 155, 195, 97, 140, 111, 133, 102, 241, 26, 176, 95, 206, 198, 71, 251,
          118, 115, 134, 215, 226, 194, 62, 106, 255, 94, 15, 142, 227, 186, 152, 88, 218, 220,
          184, 63, 242, 30, 162, 59, 32, 229>>

      assert %Cryptopunk.Key{
               chain_code:
                 <<153, 249, 145, 92, 65, 77, 50, 249, 120, 90, 178, 30, 41, 27, 73, 128, 74, 201,
                   91, 250, 143, 238, 129, 247, 115, 87, 161, 107, 123, 63, 84, 243>>,
               key:
                 <<50, 8, 92, 222, 223, 155, 132, 50, 53, 227, 114, 79, 88, 11, 248, 24, 239, 76,
                   236, 39, 195, 198, 112, 133, 224, 41, 65, 138, 91, 47, 111, 43>>,
               type: :private,
               depth: 0,
               parent_fingerprint: <<0, 0, 0, 0>>,
               index: 0
             } == Key.master_key(seed)
    end
  end

  describe "serialize/1 and deserialize/1" do
    test "serialization tests" do
      tests = [
        {"000102030405060708090a0b0c0d0e0f",
         {"xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
          "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"}},
        {"fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
         {"xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB",
          "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U"}},
        {"4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be",
         {"xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13",
          "xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6"}}
      ]

      for {seed, {ser_public_key, ser_private_key}} <- tests do
        {:ok, seed} = Base.decode16(seed, case: :lower)

        private_key = Key.master_key(seed)
        public_key = Key.public_from_private(private_key)

        assert ^ser_private_key = Key.serialize(private_key, <<4, 136, 173, 228>>)
        assert ^ser_public_key = Key.serialize(public_key, <<4, 136, 178, 30>>)

        assert private_key == Key.deserialize(ser_private_key)
        assert public_key == Key.deserialize(ser_public_key)
      end
    end
  end
end
