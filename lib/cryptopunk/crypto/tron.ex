defmodule Cryptopunk.Crypto.Tron do
  @moduledoc """
  Tron address generation logic.
  """

  alias Cryptopunk.Key
  alias Cryptopunk.Crypto.Tron.Validation

  @version_bytes %{
    mainnet: <<0x41>>,
    testnet: <<0xA0>>
  }

  @doc """
  Generate a tron address.

  It accepts two parameters:

  - public or private key. if a private key is provided, it will be converted to public key.
  - network (`:mainnet` or `:testnet`)

  Examples:

      iex> private_key = %Cryptopunk.Key{key: <<16, 42, 130, 92, 247, 244, 62, 96, 24, 129, 187, 141, 124, 42, 176, 116, 234, 171, 184, 107, 3, 229, 255, 72, 30, 116, 79, 243, 36, 142, 184, 24>>, type: :private}
      iex> Cryptopunk.Crypto.Tron.address(private_key, :mainnet)
      "TLaEVB6foF9nPn4sqscXc5jeH1PVyLwwFK"

      iex> public_key = %Cryptopunk.Key{key: <<4, 57, 163, 96, 19, 48, 21, 151, 218, 239, 65, 251, 229, 147, 160, 44, 197, 19, 208, 181, 85, 39, 236, 45, 241, 5, 14, 46, 143, 244, 156, 133, 194, 60, 190, 125, 237, 14, 124, 230, 165, 148, 137, 107, 143, 98, 136, 143, 219, 197, 200, 130, 19, 5, 226, 234, 66, 191, 1, 227, 115, 0, 17, 98, 129>>, type: :public}
      iex> Cryptopunk.Crypto.Tron.address(public_key, :testnet)
      "27PaDLFYbGN9ztPPT3YiTatLQEdEJ2xsfWM"
  """
  @spec address(Key.t(), atom()) :: String.t()
  def address(key, network \\ :mainnet)

  def address(%Key{type: :private} = private_key, network) do
    private_key
    |> Key.public_from_private()
    |> address(network)
  end

  def address(%Key{type: :public} = public_key, network) do
    public_key
    |> pub_key_64_bytes()
    |> hash_256()
    |> get_last_20_bytes()
    |> to_address(network)
  end

  defp to_address(hash, network) do
    @version_bytes
    |> Map.fetch!(network)
    |> Kernel.<>(hash)
    |> ExBase58.encode_check!()
  end

  defp hash_256(data) do
    ExKeccak.hash_256(data)
  end

  defp get_last_20_bytes(<<_::binary-12, address::binary-20>>), do: address

  defp pub_key_64_bytes(%Key{key: <<_::binary-size(1), response::binary-size(64)>>}), do: response
  defp pub_key_64_bytes(%Key{key: data}) when byte_size(data) == 64, do: data

  @spec valid?(binary()) :: boolean()
  def valid?(address) do
    Validation.valid?(address)
  end

  @spec validate_address(binary()) :: :ok | {:error, atom()}
  def validate_address(address) do
    Validation.validate_address(address)
  end
end
