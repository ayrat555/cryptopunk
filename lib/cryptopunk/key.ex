defmodule Cryptopunk.Key do
  @moduledoc """
  Utility functions to work with keys
  """
  defstruct [:type, :key, :chain_code, :depth, :index, :parent_fingerprint]

  alias Cryptopunk.Utils

  @type t :: %__MODULE__{}

  @master_hmac_key "Bitcoin seed"

  @spec new(Keyword.t()) :: t()
  def new(opts) do
    type = Keyword.fetch!(opts, :type)
    key = Keyword.fetch!(opts, :key)
    chain_code = Keyword.fetch!(opts, :chain_code)
    index = Keyword.fetch!(opts, :index)

    {depth, parent_fingerprint} =
      case Keyword.get(opts, :parent_key) do
        nil ->
          depth = Keyword.fetch!(opts, :depth)
          parent_fingerprint = Keyword.fetch!(opts, :parent_fingerprint)

          {depth, parent_fingerprint}

        parent_key ->
          depth = parent_key.depth + 1
          parent_fingerprint = fingerprint(parent_key)

          {depth, parent_fingerprint}
      end

    %__MODULE__{
      type: type,
      key: key,
      chain_code: chain_code,
      depth: depth,
      index: index,
      parent_fingerprint: parent_fingerprint
    }
  end

  @spec new_private(Keyword.t()) :: t()
  def new_private(opts) do
    opts
    |> Keyword.put(:type, :private)
    |> new()
  end

  @spec new_public(Keyword.t()) :: t()
  def new_public(opts) do
    opts
    |> Keyword.put(:type, :public)
    |> new()
  end

  @spec new_master_private(Keyword.t()) :: t()
  def new_master_private(opts) do
    opts
    |> Keyword.put(:depth, 0)
    |> Keyword.put(:parent_fingerprint, <<0::32>>)
    |> Keyword.put(:index, 0)
    |> new_private()
  end

  @spec new_master_public(Keyword.t()) :: t()
  def new_master_public(opts) do
    opts
    |> Keyword.put(:depth, 0)
    |> Keyword.put(:parent_fingerprint, <<0::32>>)
    |> Keyword.put(:index, 0)
    |> new_public()
  end

  @spec master_key(binary()) :: t()
  def master_key(seed) do
    <<private_key::binary-32, chain_code::binary-32>> = Utils.hmac_sha512(@master_hmac_key, seed)

    new_master_private(key: private_key, chain_code: chain_code)
  end

  @spec public_from_private(t()) :: t() | no_return
  def public_from_private(%__MODULE__{
        key: key,
        chain_code: chain_code,
        depth: depth,
        parent_fingerprint: parent_fingerprint,
        index: index,
        type: :private
      }) do
    {public_key, ^key} = :crypto.generate_key(:ecdh, :secp256k1, key)

    new_public(
      key: public_key,
      chain_code: chain_code,
      depth: depth,
      parent_fingerprint: parent_fingerprint,
      index: index
    )
  end

  def public_from_private(%__MODULE__{type: :public}) do
    raise ArgumentError, message: "Can not create public key"
  end

  @spec serialize(t(), binary()) :: String.t()
  def serialize(%__MODULE__{} = key, version) do
    key
    |> serialize_key()
    |> do_serialize(key, version)
    |> B58.version_encode58_check!()
  end

  defp serialize_key(%__MODULE__{type: :private, key: key}) do
    <<0::8, key::binary>>
  end

  defp serialize_key(%__MODULE__{type: :public} = public_key) do
    Utils.ser_p(public_key)
  end

  defp do_serialize(
         raw_key,
         %__MODULE__{
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

  defp fingerprint(%__MODULE__{type: :public} = key) do
    serialized = Utils.ser_p(key)
    sha256 = :crypto.hash(:sha256, serialized)

    <<fingerprint::binary-4, _rest::binary>> = :crypto.hash(:ripemd160, sha256)

    fingerprint
  end

  defp fingerprint(%__MODULE__{type: :private} = key) do
    key
    |> public_from_private()
    |> fingerprint()
  end
end
