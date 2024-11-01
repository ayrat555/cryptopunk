defmodule Cryptopunk.Crypto.Tron.ChecksumEncoding do
  @moduledoc false

  @address_length 34

  @spec valid?(String.t()) :: boolean()
  def valid?("T" <> _rest = address) when byte_size(address) == @address_length do
    case do_check_address_checksum(address) do
      :ok -> true
      {:error, _} -> false
    end
  end

  def valid?(_) do
    false
  end

  @spec validate_address(String.t()) :: :ok | {:error, atom()}
  def validate_address("T" <> _rest = address) when byte_size(address) == @address_length do
    case do_check_address_checksum(address) do
      :ok -> :ok
      {:error, reason} -> {:error, reason}
    end
  end

  def validate_address(address) do
    if String.starts_with?(address, "T") do
      {:error, :invalid_address_length}
    else
      {:error, :invalid_start_char}
    end
  end

  defp do_check_address_checksum(address) do
    case ExBase58.decode(address) do
      {:ok, <<address_without_checksum::binary-size(21), checksum::binary-size(4)>>} ->
        double_hash = address_without_checksum |> sha256() |> sha256()

        <<expected_hash::binary-size(4), _::binary>> = double_hash

        if expected_hash == checksum do
          :ok
        else
          {:error, :invalid_checksum}
        end

      {:ok, _data} ->
        {:error, :invalid_length}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp sha256(str) do
    :crypto.hash(:sha256, str)
  end
end
