defmodule Cryptopunk.Crypto.Bitcoin.P2shP2wpkhAddress do
  @moduledoc false

  alias Cryptopunk.Key
  alias Cryptopunk.Utils

  # in hex 0014
  @redeem_script_prefix <<0, 20>>

  @version_bytes %{
    mainnet: 5,
    testnet: 196
  }

  @spec address(Key.t(), atom() | non_neg_integer()) :: String.t()
  def address(public_key, net) when is_atom(net) do
    version_byte = Map.fetch!(@version_bytes, net)

    address(public_key, version_byte)
  end

  def address(public_key, version_byte) do
    key_hash =
      public_key
      |> Utils.compress_public_key()
      |> Utils.hash160()

    redeem_script = @redeem_script_prefix <> key_hash

    redeem_script
    |> Utils.hash160()
    |> ExBase58.encode_check_version!(version_byte)
  end

  @spec version_bytes() :: map()
  def version_bytes, do: @version_bytes
end
