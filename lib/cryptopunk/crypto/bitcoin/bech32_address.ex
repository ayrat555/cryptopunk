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

  @spec validate(binary()) :: {:ok, map()} | {:error, atom()}
  def validate(address) do
    case ExBech32.decode_with_version(address) do
      {:ok, {hrp, version, key_hash, _alg}} -> do_validate(hrp, version, key_hash)
      _error -> {:error, :invalid_address}
    end
  end

  @spec prefixes() :: [binary()]
  def prefixes, do: Map.values(@hrp)

  def do_validate(hrp, version, key_hash) do
    with {:ok, network} <- find_network(hrp),
         {:ok, type} <- find_type(version, key_hash) do
      {:ok, %{network: network, type: type}}
    end
  end

  defp find_network(hrp) do
    found_network =
      Enum.find(@hrp, fn {_key, value} ->
        value == hrp
      end)

    case found_network do
      nil -> {:error, :invalid_network}
      {network, _hrp} -> {:ok, network}
    end
  end

  defp find_type(version, key_hash) do
    version =
      cond do
        byte_size(key_hash) == 20 -> :p2wpkh
        version == 1 -> :p2tr
        true -> :p2wsh
      end

    {:ok, version}
  end
end
