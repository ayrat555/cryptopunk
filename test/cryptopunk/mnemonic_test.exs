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
  end
end
