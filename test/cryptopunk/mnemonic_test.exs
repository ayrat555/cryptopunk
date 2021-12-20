defmodule Cryptopunk.MnemonicTest do
  use ExUnit.Case

  alias Cryptopunk.Mnemonic

  describe "create/1" do
    test "creates mnemonic" do
      words = Mnemonic.create()

      assert 24 == words |> String.split() |> Enum.count()
    end

    test "generates different mnemonics" do
      words1 = Mnemonic.create()
      words2 = Mnemonic.create()

      assert words1 != words2
    end

    test "fails on invalid word count" do
      assert_raise ArgumentError,
                   "Number of words 10 is not supported, please use one of the [12, 15, 18, 21, 24] ",
                   fn ->
                     Mnemonic.create(10)
                   end
    end

    # https://github.com/trezor/python-mnemonic/blob/master/vectors.json
    test "verifies with bip tests" do
      %{"english" => tests} =
        File.read!("test/support/mnemonic_test.json")
        |> Jason.decode!()

      for [entropy, mnemonic, _, _] <- tests do
        {:ok, entropy} = Base.decode16(entropy, case: :lower)

        assert mnemonic == Mnemonic.create_from_entropy(entropy)
      end
    end
  end

  describe "create_from_entropy/2" do
    test "create mnemonic from the provided entropy" do
      bytes =
        <<6, 197, 169, 93, 98, 210, 82, 216, 148, 177, 1, 251, 142, 15, 154, 85, 140, 0, 13, 202,
          234, 160, 129, 218>>

      result = Mnemonic.create_from_entropy(bytes)

      expected_result =
        "almost coil firm shield cement hobby fan cage wine idea track prison scale alone close favorite limb still"

      assert expected_result == result
    end
  end
end
