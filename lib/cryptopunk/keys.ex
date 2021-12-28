defmodule Cryptopunk.Keys do
  alias Cryptopunk.DerivationPath

  @spec master_key(binary()) :: {binary(), binary()}
  def master_key(seed) do
    <<private_key::binary-32, chain_code::binary-32>> =
      :crypto.mac(:hmac, :sha512, "Bitcoin seed", seed)

    {private_key, chain_code}
  end

  @spec public_from_private(binary()) :: binary()
  def public_from_private(private_key) do
    {public_key, ^private_key} = :crypto.generate_key(:ecdh, :secp256k1, private_key)

    public_key
  end

  @spec derive(binary(), binary(), DerivationPath.t() | DerivationPath.raw_path()) :: binary()
  def derive(key, chain_code, %DerivationPath{} = path) do
    raw_path = DerivationPath.to_raw_path(path)

    derive(key, chain_code, raw_path)
  end

  def derive(key, chain_code, path) do
  end
end
