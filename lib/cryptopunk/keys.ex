defmodule Cryptopunk.Keys do
  alias Cryptopunk.DerivationPath
  alias Cryptopunk.Key
  alias Cryptopunk.Utils

  import DerivationPath, only: [is_normal: 1, is_hardened: 1]
  import Integer, only: [is_even: 1, is_odd: 1]

  @order 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

  @spec derive(Key.t(), DerivationPath.t() | DerivationPath.raw_path()) :: Key.t()
  def derive(key, %DerivationPath{} = path) do
    raw_path = DerivationPath.to_raw_path(path)

    derive(key, raw_path)
  end

  def derive(%Key{type: :public}, {:private, _}) do
    raise ArgumentError, message: "Can not derive private key from public key"
  end

  def derive(%Key{type: :private} = key, {:public, path}) do
    key
    |> do_derive(path)
    |> Key.public_from_private()
  end

  def derive(key, {_type, path}) do
    do_derive(key, path)
  end

  def do_derive(key, []), do: key

  def do_derive(%Key{chain_code: chain_code, type: :private} = private_key, [idx | tail])
      when is_normal(idx) do
    ser_public_key =
      private_key
      |> Key.public_from_private()
      |> ser_p()

    new_private_key =
      chain_code
      |> Utils.hmac_sha512(<<ser_public_key::binary, idx::32>>)
      |> create_from_private_key(private_key, idx)

    do_derive(new_private_key, tail)
  end

  def do_derive(%Key{chain_code: chain_code, key: key, type: :private} = private_key, [idx | tail])
      when is_hardened(idx) do
    new_private_key =
      chain_code
      |> Utils.hmac_sha512(<<0::8, key::binary, idx::32>>)
      |> create_from_private_key(private_key, idx)

    do_derive(new_private_key, tail)
  end

  def do_derive(%Key{chain_code: chain_code, type: :public} = public_key, [idx | tail])
      when is_normal(idx) do
    ser_public_key = ser_p(public_key)

    new_private_key =
      chain_code
      |> Utils.hmac_sha512(<<ser_public_key::binary, idx::32>>)
      |> create_from_public_key(public_key, idx)

    do_derive(new_private_key, tail)
  end

  def do_derive(%Key{type: :public}, [idx | _tail]) when is_hardened(idx) do
    raise ArgumentError, message: "Can not derive hardened key from public key"
  end

  defp create_from_public_key(
         <<l_l::binary-32, l_r::binary>>,
         %Key{key: key, type: :public} = parent_key,
         idx
       ) do
    {:ok, new_public_key} = ExSecp256k1.public_key_tweak_add(key, l_l)

    Key.new_public(
      key: new_public_key,
      chain_code: l_r,
      parent_key: parent_key,
      index: idx
    )
  end

  defp create_from_private_key(
         <<new_key::256, new_chain::binary>>,
         %Key{key: <<parent_key::256>>, type: :private} = parent_key,
         idx
       ) do
    new_private_key =
      new_key
      |> Kernel.+(parent_key)
      |> rem(@order)
      |> :binary.encode_unsigned()
      |> pad()

    Key.new_private(
      key: new_private_key,
      chain_code: new_chain,
      parent_key: parent_key,
      index: idx
    )
  end

  defp pad(binary) when byte_size(binary) >= 32, do: binary

  defp pad(binary) do
    bits = (32 - byte_size(binary)) * 8
    <<0::size(bits)>> <> binary
  end

  defp ser_p(%Key{key: <<0x04::8, x::256, y::256>>, type: :public}) when is_even(y) do
    <<0x02::8, x::256>>
  end

  defp ser_p(%Key{key: <<0x04::8, x::256, y::256>>, type: :public}) when is_odd(y) do
    <<0x03::8, x::256>>
  end
end
