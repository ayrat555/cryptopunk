defmodule Cryptopunk.Key do
  defstruct [:type, :key, :chain_code, :depth, :index, :parent_fingerprint]

  alias Cryptopunk.Utils

  @type t :: %__MODULE__{}

  @master_hmac_key "Bitcoin seed"

  @spec new(Keyword.t()) :: t()
  def new(opts) do
    type = Keyword.fetch!(opts, :type)
    key = Keyword.fetch!(opts, :key)
    chain_code = Keyword.fetch!(opts, :chain_code)
    # depth = Keyword.fetch!(opts, :depth)
    # index = Keyword.fetch!(opts, :index)
    # parent_fingerprint = Keyword.fetch!(opts, :parent_fingerprint)

    %__MODULE__{
      type: type,
      key: key,
      chain_code: chain_code
      # depth: depth,
      # index: index,
      # parent_fingerprint: parent_fingerprint
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

  @spec master_key(binary()) :: Key.t()
  def master_key(seed) do
    <<private_key::binary-32, chain_code::binary-32>> = Utils.hmac_sha512(@master_hmac_key, seed)

    new_private(key: private_key, chain_code: chain_code)
  end

  @spec public_from_private(t()) :: binary()
  def public_from_private(%__MODULE__{key: key, chain_code: chain_code, type: :private}) do
    {public_key, ^key} = :crypto.generate_key(:ecdh, :secp256k1, key)

    new_public(key: public_key, chain_code: chain_code)
  end

  @spec public_from_private(t()) :: binary()
  def public_from_private(%__MODULE__{type: :public}) do
    raise ArgumentError, message: "Can not create public key"
  end
end
