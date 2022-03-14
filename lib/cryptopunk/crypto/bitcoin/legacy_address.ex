defmodule Cryptopunk.Crypto.Bitcoin.LegacyAddress do
  @moduledoc false

  alias Cryptopunk.Key
  alias Cryptopunk.Utils

  @legacy_version_bytes %{
    mainnet: 0,
    testnet: 111
  }

  @spec address(Key.t(), atom() | binary(), Keyword.t()) :: String.t()
  def address(public_key, net, opts) when is_atom(net) do
    version_byte = Map.fetch!(@legacy_version_bytes, net)

    address(public_key, version_byte, opts)
  end

  def address(public_key, version_byte, opts) do
    {:ok, address} =
      public_key
      |> maybe_use_uncompressed_key(opts)
      |> Utils.hash160()
      |> ExBase58.encode_check_version(version_byte)

    address
  end

  def maybe_use_uncompressed_key(%Key{key: key, type: :public}, uncompressed: true), do: key

  def maybe_use_uncompressed_key(key, _opts) do
    Utils.compress_public_key(key)
  end
end
