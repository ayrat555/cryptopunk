defmodule Cryptopunk.Crypto.Ethereum do
  @moduledoc """
  Ethereum address generation logic
  """
  alias Cryptopunk.Crypto.Ethereum.ChecksumEncoding
  alias Cryptopunk.Crypto.Ethereum.Validation
  alias Cryptopunk.Key

  @doc """
  Generate an ethereum address. EVM compatible chains (for example Binance Smart Chain) may use the same address format.

  Examples:

      iex> private_key = %Cryptopunk.Key{key: <<16, 42, 130, 92, 247, 244, 62, 96, 24, 129, 187, 141, 124, 42, 176, 116, 234, 171, 184, 107, 3, 229, 255, 72, 30, 116, 79, 243, 36, 142, 184, 24>>, type: :private}
      iex> Cryptopunk.Crypto.Ethereum.address(private_key)
      "0x74510e5055179bcf406d0e7449b47dee9f81e8b7"

      iex> public_key = %Cryptopunk.Key{key: <<4, 57, 163, 96, 19, 48, 21, 151, 218, 239, 65, 251, 229, 147, 160, 44, 197, 19, 208, 181, 85, 39, 236, 45, 241, 5, 14, 46, 143, 244, 156, 133, 194, 60, 190, 125, 237, 14, 124, 230, 165, 148, 137, 107, 143, 98, 136, 143, 219, 197, 200, 130, 19, 5, 226, 234, 66, 191, 1, 227, 115, 0, 17, 98, 129>>, type: :public}
      iex> Cryptopunk.Crypto.Ethereum.address(public_key)
      "0x056db290f8ba3250ca64a45d16284d04bc6f5fbf"
  """
  @spec address(Key.t()) :: String.t()
  def address(%Key{type: :private} = private_key) do
    private_key
    |> Key.public_from_private()
    |> address()
  end

  def address(%Key{type: :public} = public_key) do
    public_key
    |> pub_key_64_bytes()
    |> hash_256()
    |> get_last_20_bytes()
    |> to_address()
  end

  @doc """
  Validate an ethereum address

  Examples:

      iex> Cryptopunk.Crypto.Ethereum.valid?("0xea0a6e3c511bbd10f4519ece37dc24887e11b55d")
      true

      iex> Cryptopunk.Crypto.Ethereum.valid?("0xea0a6e3c511bbd10f4519ece37dc24887e11b55D")
      false
  """
  @spec valid?(binary()) :: boolean()
  def valid?(address) do
    Validation.valid?(address)
  end

  @doc """
  Encode an address in the EIP-55 xixed-case checksum encoding

  Examples:

      iex> Cryptopunk.Crypto.Ethereum.checksum_encode("0xea0a6e3c511bbd10f4519ece37dc24887e11b55d")
      {:ok, "0xea0A6E3c511bbD10f4519EcE37Dc24887e11b55d"}

      iex> Cryptopunk.Crypto.Ethereum.checksum_encode("0x52908400098527886e0f7030069857d2e4169ee7")
      {:ok, "0x52908400098527886E0F7030069857D2E4169EE7"}

      iex> Cryptopunk.Crypto.Ethereum.checksum_encode("0x52908400098527886e0f7030069857d2e4169ee")
      {:error, :invalid_address_length}
  """
  @spec checksum_encode(String.t()) ::
          {:ok, String.t()}
          | {:error, {:unknown_char, String.t()}}
          | {:error, :invalid_address_length}
  def checksum_encode(address) do
    ChecksumEncoding.encode(address)
  end

  defp to_address(public_hash) do
    address = Base.encode16(public_hash, case: :lower)

    "0x" <> address
  end

  defp hash_256(data) do
    ExKeccak.hash_256(data)
  end

  defp get_last_20_bytes(<<_::binary-12, address::binary-20>>), do: address

  defp pub_key_64_bytes(%Key{key: <<_::binary-size(1), response::binary-size(64)>>}), do: response
  defp pub_key_64_bytes(%Key{key: data}) when byte_size(data) == 64, do: data
end
