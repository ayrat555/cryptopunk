defmodule Cryptopunk.Crypto.Bitcoin do
  @moduledoc """
  Bitcoin address generation logic
  """

  alias Cryptopunk.B58
  alias Cryptopunk.Key
  alias Cryptopunk.Utils

  @version_bytes %{
    mainnet: <<0x00>>,
    testnet: <<0x6F>>
  }

  @spec address(Key.t(), atom()) :: String.t()
  def address(private_or_public_key, net)

  def address(%Key{type: :private} = private_key, net) do
    private_key
    |> Key.public_from_private()
    |> address(net)
  end

  def address(%Key{type: :public} = public_key, net) do
    version = Map.fetch!(@version_bytes, net)

    public_key
    |> Utils.compress_public_key()
    |> Utils.sha256_hash()
    |> Utils.ripemd160_hash()
    |> B58.encode58_check!(version)
  end
end
