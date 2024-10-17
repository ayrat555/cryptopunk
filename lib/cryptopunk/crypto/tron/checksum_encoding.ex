defmodule Cryptopunk.Crypto.Tron.ChecksumEncoding do
  @moduledoc false

  @address_length 34

  @spec valid?(String.t()) :: boolean()
  def valid?(address) do
    String.starts_with?(address, "T") && String.length(address) == @address_length &&
      do_check_address_checksum(address)
  end

  defp do_check_address_checksum(address) do
    with {:ok, binary} <-
           ExBase58.decode(address) do
      <<address_without_checksum::binary-size(byte_size(binary) - 4), checksum::binary-size(4)>> =
        binary

      checksum = checksum |> Base.encode16(case: :lower)

      double_hash =
        address_without_checksum
        |> Base.encode16(case: :lower)
        |> ExKeccak.hash_256()
        |> ExKeccak.hash_256()

      <<expected_hash::binary-size(8), _::binary>> = double_hash

      IO.inspect(expected_hash |> Base.encode16(case: :lower))

      IO.inspect(checksum)
    else
      {:error, :invalid_alphabet} -> {:error, :invalid_alphabet}
      {:error, :decode_error} -> {:error, :decode_error}
    end
  end
end
