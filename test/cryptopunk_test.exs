defmodule CryptopunkTest do
  use ExUnit.Case
  doctest Cryptopunk

  test "greets the world" do
    assert Cryptopunk.hello() == :world
  end
end
