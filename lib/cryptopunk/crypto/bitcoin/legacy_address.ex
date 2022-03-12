defmodule Cryptopunk.Crypto.Bitcoin.LegacyAddress do
  @moduledoc false

  alias Cryptopunk.Key
  alias Cryptopunk.Utils

  @legacy_version_bytes %{
    mainnet: 0,
    testnet: 111
  }

  @spec address(Key.t(), atom() | binary()) :: String.t()
  def address(public_key, net) when is_atom(net) do
    version_byte = Map.fetch!(@legacy_version_bytes, net)

    address(public_key, version_byte)
  end

  def address(public_key, version_byte) do
    {:ok, address} =
      public_key
      |> Utils.compress_public_key()
      |> Utils.hash160()
      |> ExBase58.encode_check_version(version_byte)

    address
  end
end
