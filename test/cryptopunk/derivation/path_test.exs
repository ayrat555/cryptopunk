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

  describe "parse_incomplete_path/1" do
    test "parsed an incomplete path" do
      path = "M/100/99'/10'/9/1000'"

      assert {:ok,
              {
                :public,
                [
                  100,
                  Path.two_power_31() + 99,
                  Path.two_power_31() + 10,
                  9,
                  Path.two_power_31() + 1000
                ]
              }} ==
               Path.parse_incomplete_path(path)
    end

    test "fails to parth path if type is invalid" do
      path = "T/99/11"

      assert {:error, {:invalid_level, :type}} ==
               Path.parse_incomplete_path(path)
    end

    test "parse incomplete regular paths" do
      paths = [
        {"M/84'/0'/0'", {:public, [2_147_483_732, 2_147_483_648, 2_147_483_648]}},
        {"M/49'/0'/0'", {:public, [2_147_483_697, 2_147_483_648, 2_147_483_648]}},
        {"M/44'/0'/0'", {:public, [2_147_483_692, 2_147_483_648, 2_147_483_648]}}
      ]

      Enum.each(paths, fn {str_path, expected} ->
        assert {:ok, expected} == Path.parse_incomplete_path(str_path)
      end)
    end
  end
end
