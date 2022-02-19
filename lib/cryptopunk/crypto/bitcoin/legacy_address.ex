defmodule Cryptopunk.Crypto.Bitcoin.LegacyAddress do
  @moduledoc false

  alias Cryptopunk.B58
  alias Cryptopunk.Key
  alias Cryptopunk.Utils

  @legacy_version_bytes %{
    mainnet: <<0x00>>,
    testnet: <<0x6F>>
  }

  @spec address(Key.t(), atom() | binary()) :: String.t()
  def address(public_key, net) when is_atom(net) do
    version_byte = Map.fetch!(@legacy_version_bytes, net)

    address(public_key, version_byte)
  end

  def address(public_key, version_byte) do
    public_key
    |> Utils.compress_public_key()
    |> Utils.hash160()
    |> B58.encode58_check!(version_byte)
  end
end
