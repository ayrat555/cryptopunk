defmodule Cryptopunk.Crypto.Dogecoin do
  @moduledoc """
  Dogecoin address generation logic. It's similar to bitcoin legacy addresses.
  """

  alias Cryptopunk.Crypto.Bitcoin
  alias Cryptopunk.Key

  @version_bytes %{
    mainnet: <<0x1E>>,
    testnet: <<0x71>>
  }

  @doc """
  Generate a dogecoin address.

  It accepts two parameters:

  - public or private key. if a private key is provided, it will be converted to public key.
  - network (`:mainnet` or `:testnet`)

  Examples:

      iex> private_key = %Cryptopunk.Key{key: <<16, 42, 130, 92, 247, 244, 62, 96, 24, 129, 187, 141, 124, 42, 176, 116, 234, 171, 184, 107, 3, 229, 255, 72, 30, 116, 79, 243, 36, 142, 184, 24>>, type: :private}
      iex> Cryptopunk.Crypto.Dogecoin.address(private_key, :mainnet)
      "DNoni2tA31AaaRgdSKnzBXyvTTFyabwPKi"

      iex> public_key = %Cryptopunk.Key{key: <<4, 57, 163, 96, 19, 48, 21, 151, 218, 239, 65, 251, 229, 147, 160, 44, 197, 19, 208, 181, 85, 39, 236, 45, 241, 5, 14, 46, 143, 244, 156, 133, 194, 60, 190, 125, 237, 14, 124, 230, 165, 148, 137, 107, 143, 98, 136, 143, 219, 197, 200, 130, 19, 5, 226, 234, 66, 191, 1, 227, 115, 0, 17, 98, 129>>, type: :public}
      iex> Cryptopunk.Crypto.Dogecoin.address(public_key, :testnet)
      "nYxUariD3FNhvYrgVHGQk6y68aBtLHP87b"
  """
  @spec address(Key.t(), atom()) :: String.t()
  def address(private_or_public_key, net) do
    version_byte = Map.fetch!(@version_bytes, net)

    Bitcoin.legacy_address(private_or_public_key, version_byte)
  end
end
