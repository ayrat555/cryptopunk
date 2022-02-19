defmodule Cryptopunk.Crypto.Bitcoin do
  @moduledoc """
  Bitcoin address generation logic
  """

  alias Cryptopunk.Crypto.Bitcoin.LegacyAddress
  alias Cryptopunk.Crypto.Bitcoin.P2shP2wpkhAddress
  alias Cryptopunk.Key

  @spec legacy_address(Key.t(), atom() | binary()) :: String.t()
  def legacy_address(private_or_public_key, net_or_version_byte) do
    address(private_or_public_key, net_or_version_byte, :legacy)
  end

  @spec legacy_address(Key.t(), atom() | binary()) :: String.t()
  def p2sh_p2wpkh_address(private_or_public_key, net_or_version_byte) do
    address(private_or_public_key, net_or_version_byte, :p2sh_p2wpkh)
  end

  defp address(%Key{type: :private} = private_key, net_or_version_byte, type) do
    private_key
    |> Key.public_from_private()
    |> generate_address(net_or_version_byte, type)
  end

  defp address(%Key{type: :public} = public_key, net_or_version_byte, type) do
    generate_address(public_key, net_or_version_byte, type)
  end

  defp generate_address(public_key, net_or_version_byte, :legacy) do
    LegacyAddress.address(public_key, net_or_version_byte)
  end

  defp generate_address(public_key, net_or_version_byte, :p2sh_p2wpkh) do
    P2shP2wpkhAddress.address(public_key, net_or_version_byte)
  end
end
