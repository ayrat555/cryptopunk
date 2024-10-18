defmodule Cryptopunk.Crypto.Tron.ChecksumEncoding do
  @moduledoc false

  @address_length 34

  @spec valid?(String.t()) :: boolean()
  def valid?(address) do
    String.starts_with?(address, "T") && String.length(address) == @address_length &&
      do_check_address_checksum(address)
  end

  defp do_check_address_checksum(address) do
    with {:ok, bin} <-
           ExBase58.decode(address) do
      <<address_without_checksum::binary-size(byte_size(bin) - 4), checksum::binary-size(4)>> =
        bin

      checksum = checksum |> Base.encode16(case: :lower)

      double_hash =
        address_without_checksum
        |> Base.encode16(case: :lower)

      double_hash =
        :crypto.hash(:sha3_256, double_hash)
        |> Base.encode16(case: :lower)

      double_hash =
        :crypto.hash(:sha3_256, double_hash)

      <<expected_hash::binary-size(4), _::binary>> = double_hash

      IO.inspect("#{expected_hash |> Base.encode16(case: :lower)} == #{checksum}")
    else
      {:error, :invalid_alphabet} -> {:error, :invalid_alphabet}
      {:error, :decode_error} -> {:error, :decode_error}
    end
  end
end
