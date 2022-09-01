defmodule Cryptopunk.DerivationTest do
  use ExUnit.Case

  alias Cryptopunk.Derivation
  alias Cryptopunk.Derivation.Path
  alias Cryptopunk.Key

  @private_key %Cryptopunk.Key{
    chain_code:
      <<153, 249, 145, 92, 65, 77, 50, 249, 120, 90, 178, 30, 41, 27, 73, 128, 74, 201, 91, 250,
        143, 238, 129, 247, 115, 87, 161, 107, 123, 63, 84, 243>>,
    key:
      <<50, 8, 92, 222, 223, 155, 132, 50, 53, 227, 114, 79, 88, 11, 248, 24, 239, 76, 236, 39,
        195, 198, 112, 133, 224, 41, 65, 138, 91, 47, 111, 43>>,
    type: :private,
    depth: 0,
    parent_fingerprint: <<0, 0, 0, 0>>,
    index: 0
  }

  describe "derive/2" do
    test "derives private key from private key" do
      {:ok, path} = Path.parse("m / 44' / 0' / 0' / 0 / 0")

      assert %Cryptopunk.Key{
               chain_code:
                 <<166, 125, 2, 213, 77, 88, 124, 145, 241, 251, 83, 163, 21, 11, 20, 34, 158,
                   157, 179, 147, 162, 212, 148, 89, 28, 92, 68, 126, 215, 79, 147, 159>>,
               key:
                 <<214, 231, 94, 203, 167, 219, 125, 43, 251, 91, 147, 51, 32, 146, 186, 215, 58,
                   45, 104, 58, 119, 114, 121, 238, 155, 215, 239, 189, 37, 236, 27, 70>>,
               index: 0,
               depth: 5,
               parent_fingerprint: <<205, 94, 166, 92>>,
               type: :private
             } == Derivation.derive(@private_key, path)
    end

    test "derives public key from private key" do
      {:ok, path} = Path.parse("M / 44' / 0' / 0' / 0 / 0")

      assert %Cryptopunk.Key{
               chain_code:
                 <<166, 125, 2, 213, 77, 88, 124, 145, 241, 251, 83, 163, 21, 11, 20, 34, 158,
                   157, 179, 147, 162, 212, 148, 89, 28, 92, 68, 126, 215, 79, 147, 159>>,
               depth: 5,
               index: 0,
               key:
                 <<4, 225, 210, 45, 140, 51, 233, 5, 161, 220, 196, 43, 7, 62, 165, 169, 118, 71,
                   56, 83, 210, 98, 146, 155, 159, 184, 134, 183, 227, 69, 40, 106, 142, 42, 28,
                   130, 36, 216, 210, 243, 83, 206, 189, 167, 217, 243, 15, 89, 183, 17, 231, 243,
                   38, 213, 158, 97, 206, 197, 70, 213, 10, 189, 84, 112, 190>>,
               parent_fingerprint: <<205, 94, 166, 92>>,
               type: :public
             } == Derivation.derive(@private_key, path)
    end

    test "derives public key from public key" do
      public_key = Key.public_from_private(@private_key)

      assert %Cryptopunk.Key{
               chain_code:
                 <<1, 128, 231, 93, 205, 226, 38, 167, 33, 154, 71, 27, 244, 231, 8, 150, 102,
                   238, 86, 75, 84, 62, 31, 108, 190, 242, 89, 244, 10, 42, 223, 228>>,
               key:
                 <<4, 72, 74, 200, 28, 232, 245, 83, 17, 29, 169, 231, 121, 159, 114, 42, 96, 220,
                   235, 130, 36, 23, 219, 35, 71, 145, 101, 168, 91, 19, 86, 89, 162, 24, 61, 72,
                   197, 216, 155, 51, 37, 158, 231, 29, 220, 79, 29, 241, 231, 84, 132, 70, 57,
                   72, 58, 150, 84, 55, 52, 40, 212, 64, 158, 65, 49>>,
               depth: 2,
               index: 1,
               parent_fingerprint: <<28, 178, 137, 192>>,
               type: :public
             } == Derivation.derive(public_key, {:public, [1, 1]})
    end

    test "fails to derive private key from public key" do
      public_key = Key.public_from_private(@private_key)

      assert_raise ArgumentError, "Can not derive private key from public key", fn ->
        Derivation.derive(public_key, {:private, [1, 1]})
      end
    end

    test "fails to derive hardened from public key" do
      public_key = Key.public_from_private(@private_key)

      assert_raise ArgumentError, "Can not derive hardened key from public key", fn ->
        Derivation.derive(public_key, {:public, [2_147_483_649, 1]})
      end
    end

    test "bip32 tests" do
      seed_data =
        "test/support/bip32_test.json"
        |> File.read!()
        |> Jason.decode!()

      for {raw_seed, tests} <- seed_data do
        seed = Base.decode16!(raw_seed, case: :lower)
        private_key = Key.master_key(seed)

        for [path, xpub, xpriv] <- tests do
          parsed_path = parse_path(path)

          derived_private_key = Derivation.derive(private_key, {:private, parsed_path})
          serialized_key = Key.serialize(derived_private_key, <<4, 136, 173, 228>>)
          assert serialized_key == xpriv

          derived_public_key = Derivation.derive(private_key, {:public, parsed_path})
          serialized_key = Key.serialize(derived_public_key, <<4, 136, 178, 30>>)

          assert serialized_key == xpub
        end
      end
    end
  end

  defp parse_path(path) do
    ["m" | idxs] = String.split(path, "/")

    formatted_idxs =
      idxs
      |> Enum.reverse()
      |> format_idxs()

    formatted_idxs
  end

  defp format_idxs(idxs, acc \\ [])

  defp format_idxs([], acc), do: acc

  defp format_idxs([current_id | tail], acc) do
    formatted_id =
      if String.ends_with?(current_id, "H") do
        {id, "H"} = Integer.parse(current_id)

        id + Path.two_power_31()
      else
        {id, ""} = Integer.parse(current_id)

        id
      end

    format_idxs(tail, [formatted_id | acc])
  end
end
