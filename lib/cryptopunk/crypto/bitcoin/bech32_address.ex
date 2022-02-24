defmodule Cryptopunk.Crypto.Bitcoin.Bech32Address do
  @moduledoc false

  alias Cryptopunk.Key
  alias Cryptopunk.Utils

  @default_version 0

  @version_to_variant %{
    0 => :bech32,
    1 => :bech32m
  }

  @hrp %{mainnet: "bc", testnet: "tb", regtest: "bcrt"}

  @spec address(Key.t(), atom() | binary(), Keyword.t()) :: String.t()
  def address(public_key, net, opts) when is_atom(net) do
    hrp = Map.fetch!(@hrp, net)

    address(public_key, hrp, opts)
  end

  def address(public_key, hrp, opts) do
    version = Keyword.get(opts, :version, @default_version)
    bech32_version = Map.fetch!(@version_to_variant, version)

    key_hash =
      public_key
      |> Utils.compress_public_key()
      |> Utils.hash160()

    {:ok, address} = ExBech32.encode_with_version(hrp, version, key_hash, bech32_version)

    address
  end
end
