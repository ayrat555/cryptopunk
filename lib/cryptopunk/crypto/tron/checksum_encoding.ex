defmodule Cryptopunk.Crypto.Tron.ChecksumEncoding do
  @moduledoc false

  @address_length 34

  @spec valid?(String.t()) :: boolean()
  def valid?(address) do
    String.starts_with?(address, "T") && String.length(address) == @address_length &&
      do_check_address_checksum(address)
  end

  defp sha256(str) do
    :crypto.hash(:sha256, str)
  end

  defp do_check_address_checksum(address) do
    with {:ok, decoded} <-
           ExBase58.decode(address) do
      <<address_without_checksum::binary-size(byte_size(decoded) - 4), checksum::binary-size(4)>> =
        decoded

      double_hash = address_without_checksum |> sha256() |> sha256()

      <<expected_hash::binary-size(4), _::binary>> = double_hash

      expected_hash == checksum
    else
      {:error, :invalid_alphabet} -> {:error, :invalid_alphabet}
      {:error, :decode_error} -> {:error, :decode_error}
    end
  end
end
