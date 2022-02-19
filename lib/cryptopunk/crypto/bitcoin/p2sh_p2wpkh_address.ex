defmodule Cryptopunk.Crypto.Bitcoin.P2shP2wpkhAddress do
  @moduledoc false

  alias Cryptopunk.B58
  alias Cryptopunk.Key
  alias Cryptopunk.Utils

  # in hex 0014
  @redeem_script_prefix <<0, 20>>

  @version_bytes %{
    mainnet: <<0x05>>,
    testnet: <<0xC4>>
  }

  @spec address(Key.t(), atom() | binary()) :: String.t()
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
    script_sig = Utils.hash160(redeem_script)

    B58.encode58_check!(script_sig, version_byte)
  end
end
