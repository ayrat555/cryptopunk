defmodule Cryptopunk.Derivation.PathTest do
  use ExUnit.Case

  alias Cryptopunk.Derivation.Path

  describe "parse/1" do
    test "parses path" do
      path = "m/44'/2'/0'/0/1"

      assert {:ok,
              %Path{
                account: 0,
                address_index: 1,
                change: 0,
                coin_type: 2,
                purpose: 44,
                type: :private
              }} = Path.parse(path)
    end

    test "fails to parse invalid string" do
      assert {:error, :invalid_path} = Path.parse("invalid")
    end

    test "fails is the level is not hardened" do
      path = "m/44'/2 /0'/0/1"

      assert {:error, {:invalid_level, :coin_type}} = Path.parse(path)
    end
  end

  describe "to_raw_path/1" do
    test "converts to raw path" do
      path = %Path{
        account: 0,
        address_index: 1,
        change: 0,
        coin_type: 2,
        purpose: 44,
        type: :private
      }

      assert {:private, [2_147_483_692, 2_147_483_650, 2_147_483_648, 0, 1]} =
               Path.to_raw_path(path)
    end
  end
end
