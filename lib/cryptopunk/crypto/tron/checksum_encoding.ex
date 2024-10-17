defmodule Cryptopunk.Crypto.Tron.ChecksumEncoding do
  @moduledoc false

  @address_length 34

  @spec encode(String.t()) ::
          {:ok, String.t()}
          | {:error, {:unknown_char, String.t()}}
          | {:error, :invalid_address_length}
  def encode("T" <> address) do
    encode(address)
  end

  def encode(address) when byte_size(address) == @address_length do
    address = String.downcase(address)
    
    # TO IMPLEMENT

  end

  def encode(_address) do
    {:error, :invalid_address_length}
  end

  @spec valid?(String.t()) :: boolean()
  def valid?("T" <> address) do
    valid?(address)
  end

  def valid?(address) do
    String.length(address) == @address_length && do_check_address_checksum(address)
  end

  defp do_check_address_checksum(address) do
    case encode(address) do
      {:ok, "T" <> ^address} -> true
      _ -> false
    end
  end
end
