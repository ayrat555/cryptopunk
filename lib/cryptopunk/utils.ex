defmodule Cryptopunk.Utils do
  @moduledoc """
  Utility functions
  """

  alias Cryptopunk.Key

  @spec hmac_sha512(binary(), binary()) :: binary()
  def hmac_sha512(key, data) do
    :crypto.mac(:hmac, :sha512, key, data)
  end

  @spec compress_public_key(Key.t()) :: binary()
  def compress_public_key(%Key{key: key, type: :public}) do
    {:ok, compressed} = ExSecp256k1.public_key_compress(key)

    compressed
  end

  @spec decompress_public_key(binary()) :: binary()
  def decompress_public_key(key) do
    {:ok, decompressed} = ExSecp256k1.public_key_decompress(key)

    decompressed
  end

  @spec sha256_hash(binary()) :: binary()
  def sha256_hash(binary) do
    :crypto.hash(:sha256, binary)
  end

  @spec ripemd160_hash(binary()) :: binary()
  def ripemd160_hash(binary) do
    :crypto.hash(:ripemd160, binary)
  end
end
