defmodule Cryptopunk.SeedTest do
  use ExUnit.Case

  alias Cryptopunk.Mnemonic
  alias Cryptopunk.Seed

  describe "create/1" do
    test "creates seed from string" do
      password = "hey"
      salt = "mnemonic"
      result = Seed.create(password)

      assert 64 = byte_size(result)

      opts = %{alg: "sha512", iterations: 2048, length: 64, salt: salt}

      assert ExPBKDF2.verify(result, "hey", opts)
    end

    test "Mastering bitcoin book tests" do
      tests = [
        {"5b56c417303faa3fcba7e57400e120a0ca83ec5a4fc9ffba757fbe63fbd77a89a1a3be4c67196f57c39a88b76373733891bfaba16ed27a813ceed498804c0570",
         ""},
        {"3b5df16df2157104cfdd22830162a5e170c0161653e3afe6c88defeefb0818c793dbb28ab3ab091897d0715861dc8a18358f80b79d49acf64142ae57037d1d54",
         "SuperDuperSecret"}
      ]

      for {expected_result, pass} <- tests do
        result =
          "army van defense carry jealous true garbage claim echo media make crunch"
          |> Seed.create(pass)
          |> Base.encode16(case: :lower)

        assert expected_result == result
      end
    end

    test "Mastering bitcoin book test" do
      expected_result =
        "3269bce2674acbd188d4f120072b13b088a0ecf87c6e4cae41657a0bb78f5315b33b3a04356e53d062e55f1e0deaa082df8d487381379df848a6ad7e98798404"

      entropy =
        "2041546864449caff939d32d574753fe684d3c947c3346713dd8423e74abcf8c"
        |> Base.decode16!(case: :lower)

      mnemonic = Mnemonic.create_from_entropy(entropy)

      result = mnemonic |> Seed.create() |> Base.encode16(case: :lower)

      assert expected_result == result
    end
  end
end
