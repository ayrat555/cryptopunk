defmodule Cryptopunk.Key do
  @moduledoc """
  Utility functions to work with keys
  """
  defstruct [:type, :key, :chain_code, :depth, :index, :parent_fingerprint]

  alias Cryptopunk.Key.Serialization
  alias Cryptopunk.Utils

  @type t :: %__MODULE__{
          type: :private | :public,
          key: binary(),
          chain_code: binary(),
          depth: non_neg_integer(),
          index: non_neg_integer(),
          parent_fingerprint: binary()
        }

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
    {:ok, public_key} = ExSecp256k1.create_public_key(key)

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
  def serialize(key, version) do
    Serialization.encode(key, version)
  end

  @spec deserialize(binary()) :: t()
  def deserialize(encoded_key) do
    Serialization.decode(encoded_key)
  end

  defp fingerprint(%__MODULE__{type: :public} = key) do
    serialized = Utils.compress_public_key(key)
    sha256 = Utils.sha256_hash(serialized)

    <<fingerprint::binary-4, _rest::binary>> = Utils.ripemd160_hash(sha256)

    fingerprint
  end

  defp fingerprint(%__MODULE__{type: :private} = key) do
    key
    |> public_from_private()
    |> fingerprint()
  end
end
