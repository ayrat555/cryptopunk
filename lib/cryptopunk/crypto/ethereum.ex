defmodule Cryptopunk.Crypto.Ethereum do
  @moduledoc """
  Ethereum address generation logic
  """
  alias Cryptopunk.Key

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
