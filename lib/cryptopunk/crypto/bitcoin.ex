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

  @spec address(Key.t(), atom() | binary()) :: String.t()
  def address(private_or_public_key, net)

  def address(%Key{type: :private} = private_key, net) do
    private_key
    |> Key.public_from_private()
    |> address(net)
  end

  def address(%Key{type: :public} = public_key, version_byte) when is_binary(version_byte) do
    generate_address(public_key, version_byte)
  end

  def address(%Key{type: :public} = public_key, net) when is_atom(net) do
    version_byte = Map.fetch!(@version_bytes, net)

    generate_address(public_key, version_byte)
  end

  defp generate_address(public_key, version_byte) do
    public_key
    |> Utils.compress_public_key()
    |> Utils.sha256_hash()
    |> Utils.ripemd160_hash()
    |> B58.encode58_check!(version_byte)
  end
end
