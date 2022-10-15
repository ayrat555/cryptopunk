defmodule Cryptopunk.Crypto.Ethereum.ChecksumEncoding do
  @moduledoc false

  @address_length 40

  @spec encode(String.t()) ::
          {:ok, String.t()}
          | {:error, {:unknown_char, String.t()}}
          | {:error, :invalid_address_length}
  def encode("0x" <> address) do
    encode(address)
  end

  def encode(address) when byte_size(address) == @address_length do
    address = String.downcase(address)

    nibles =
      address
      |> ExKeccak.hash_256()
      |> Base.encode16(case: :lower)
      |> String.graphemes()
      |> Enum.map(fn hashed_character ->
        {nible, ""} = Integer.parse(hashed_character, 16)

        nible
      end)

    address
    |> String.graphemes()
    |> Enum.zip(nibles)
    |> Enum.reduce_while("", fn {character, nible}, acc ->
      cond do
        character in ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"] ->
          {:cont, acc <> character}

        character in ["a", "b", "c", "d", "e", "f"] && nible > 7 ->
          {:cont, acc <> String.upcase(character)}

        character in ["a", "b", "c", "d", "e", "f"] ->
          {:cont, acc <> character}

        true ->
          {:halt, {:error, {:unknown_char, character}}}
      end
    end)
    |> case do
      {:error, _} = error -> error
      result -> {:ok, "0x" <> result}
    end
  end

  def encode(_address) do
    {:error, :invalid_address_length}
  end

  @spec valid?(String.t()) :: boolean()
  def valid?("0x" <> address) do
    valid?(address)
  end

  def valid?(address) do
    String.length(address) == @address_length && do_check_address_checksum(address)
  end

  defp do_check_address_checksum(address) do
    case encode(address) do
      {:ok, "0x" <> ^address} -> true
      _ -> false
    end
  end
end
