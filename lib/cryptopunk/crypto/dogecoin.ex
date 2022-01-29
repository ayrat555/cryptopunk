defmodule Cryptopunk.Crypto.Dogecoin do
  @moduledoc """
  Dogecoin address generation logic. It's similar to bitcoin
  """

  alias Cryptopunk.Crypto.Bitcoin
  alias Cryptopunk.Key

  @version_bytes %{
    mainnet: <<0x1E>>,
    testnet: <<0x71>>
  }

  @spec address(Key.t(), atom()) :: String.t()
  def address(private_or_public_key, net) do
    version_byte = Map.fetch!(@version_bytes, net)

    Bitcoin.address(private_or_public_key, version_byte)
  end
end
