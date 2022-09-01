defmodule Cryptopunk.Key.WIF do
  @moduledoc """
  Wallet import format (WIF) encoding
  """

  alias Cryptopunk.Key

  @network %{
    mainnet: <<0x80>>,
    testnet: <<0xEF>>
  }

  @compression <<0x01>>

  @spec encode(Key.t() | binary(), Keyword.t()) :: binary()
  def encode(%Key{key: key, type: :private}, params) do
    encode(key, params)
  end

  def encode(key, params) when is_binary(key) do
    network = network(params)
    compression = compression(params)

    ExBase58.encode_check!(network <> key <> compression)
  end

  @spec decode(binary(), Keyword.t()) :: binary()
  def decode(encoded_key, params) do
    network = network(params)
    compression = compression(params)

    <<^network::binary-size(1), key::binary-32, ^compression::binary>> =
      ExBase58.decode_check!(encoded_key)

    key
  end

  defp network(params) do
    network = Keyword.fetch!(params, :network)

    cond do
      network in Map.keys(@network) ->
        Map.fetch!(@network, network)

      is_binary(network) ->
        network

      true ->
        raise ArgumentError,
          message: "Network is invalid "
    end
  end

  defp compression(params) do
    if Keyword.get(params, :compression, true) do
      @compression
    else
      <<>>
    end
  end
end
