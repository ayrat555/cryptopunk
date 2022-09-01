defmodule Cryptopunk.Key.Serialization do
  @moduledoc """
  Extended key serialization logic
  """

  alias Cryptopunk.Key
  alias Cryptopunk.Utils

  @spec encode(Key.t(), binary()) :: String.t() | no_return()
  def encode(%Key{} = key, version) do
    key
    |> encode_key()
    |> do_encode(key, version)
    |> ExBase58.encode_check!()
  end

  @spec decode(binary()) :: Key.t()
  def decode(<<"xpub", _rest::binary>> = encoded_key) do
    do_decode(encoded_key, :public)
  end

  def decode(<<"xprv", _rest::binary>> = encoded_key) do
    do_decode(encoded_key, :private)
  end

  defp encode_key(%Key{type: :private, key: key}) do
    <<0::8, key::binary>>
  end

  defp encode_key(%Key{type: :public} = public_key) do
    Utils.compress_public_key(public_key)
  end

  defp do_encode(
         raw_key,
         %Key{
           chain_code: chain_code,
           depth: depth,
           index: index,
           parent_fingerprint: fingerprint
         },
         version
       ) do
    <<
      version::binary,
      depth::8,
      fingerprint::binary,
      index::32,
      chain_code::binary,
      raw_key::binary
    >>
  end

  defp do_decode(encoded_key, type) do
    <<
      _version_number::binary-4,
      depth::8,
      fingerprint::binary-4,
      index::32,
      chain_code::binary-32,
      key::binary-33
    >> = ExBase58.decode_check!(encoded_key)

    %Key{
      type: type,
      key: deserialize_key(key, type),
      chain_code: chain_code,
      depth: depth,
      index: index,
      parent_fingerprint: fingerprint
    }
  end

  defp deserialize_key(<<0::8, key::binary>>, :private), do: key

  defp deserialize_key(key, :public) do
    Utils.decompress_public_key(key)
  end
end
