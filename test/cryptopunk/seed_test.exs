defmodule Cryptopunk.SeedTest do
  use ExUnit.Case

  alias Cryptopunk.Seed

  describe "create/1" do
    test "creates seed from string" do
      password = "hey"
      salt = "mnemonic"
      result = Seed.create(password)

      assert 64 = byte_size(result)

      opts = %{alg: "sha512", iterations: 2048, length: 64, salt: salt}

      assert result
             |> Base.encode64(padding: false)
             |> ExPBKDF2.verify("hey", opts)
    end
  end
end
