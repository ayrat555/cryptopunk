defmodule Cryptopunk.Crypto.Bitcoin.LegacyAddress do
  @moduledoc false

  alias Cryptopunk.Key
  alias Cryptopunk.Utils

  @version_bytes %{
    mainnet: 0,
    testnet: 111
  }

  @spec address(Key.t(), atom() | non_neg_integer(), Keyword.t()) :: String.t()
  def address(public_key, net, opts \\ [])

  def address(public_key, net, opts) when is_atom(net) do
    version_byte = Map.fetch!(@version_bytes, net)

    address(public_key, version_byte, opts)
  end

  def address(public_key, version_byte, opts) do
    public_key
    |> maybe_use_uncompressed_key(opts)
    |> Utils.hash160()
    |> ExBase58.encode_check_version!(version_byte)
  end

  @spec version_bytes() :: map()
  def version_bytes, do: @version_bytes

  defp maybe_use_uncompressed_key(%Key{key: key, type: :public}, uncompressed: true), do: key

  defp maybe_use_uncompressed_key(key, _opts) do
    Utils.compress_public_key(key)
  end
end
