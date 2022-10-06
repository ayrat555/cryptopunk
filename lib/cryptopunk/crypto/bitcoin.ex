defmodule Cryptopunk.Crypto.Bitcoin do
  @moduledoc """
  Bitcoin address generation logic.

  All addresses use compressed public keys.
  """

  alias Cryptopunk.Crypto.Bitcoin.Bech32Address
  alias Cryptopunk.Crypto.Bitcoin.LegacyAddress
  alias Cryptopunk.Crypto.Bitcoin.P2shP2wpkhAddress
  alias Cryptopunk.Key

  @doc """
  Generate a legacy (P2PKH) address.

  It accepts three parameters:

  - public or private key. if a private key is provided, it will be converted to public key.
  - network (`:mainnet` or `:testnet`)
  - optional keyword params. Currently, the only allowed parameter is `:uncompressed` key. Passing `[uncompressed: true]` will generate the address from the uncompressed public key which is not advised. but it may be required for compatibility reasons

  Examples:

      iex> private_key = %Cryptopunk.Key{key: <<16, 42, 130, 92, 247, 244, 62, 96, 24, 129, 187, 141, 124, 42, 176, 116, 234, 171, 184, 107, 3, 229, 255, 72, 30, 116, 79, 243, 36, 142, 184, 24>>, type: :private}
      iex> Cryptopunk.Crypto.Bitcoin.legacy_address(private_key, :mainnet)
      "1JfhAmwWjbGJ3RW2hjoRdmpKaKXgCjSwEL"

      iex> public_key = %Cryptopunk.Key{key: <<4, 57, 163, 96, 19, 48, 21, 151, 218, 239, 65, 251, 229, 147, 160, 44, 197, 19, 208, 181, 85, 39, 236, 45, 241, 5, 14, 46, 143, 244, 156, 133, 194, 60, 190, 125, 237, 14, 124, 230, 165, 148, 137, 107, 143, 98, 136, 143, 219, 197, 200, 130, 19, 5, 226, 234, 66, 191, 1, 227, 115, 0, 17, 98, 129>>, type: :public}
      iex> Cryptopunk.Crypto.Bitcoin.legacy_address(public_key, :testnet)
      "mkHGce7dctSxHgaWSSbmmrRWsZfzz7MxMk"

      iex> private_key = %Cryptopunk.Key{key: <<16, 42, 130, 92, 247, 244, 62, 96, 24, 129, 187, 141, 124, 42, 176, 116, 234, 171, 184, 107, 3, 229, 255, 72, 30, 116, 79, 243, 36, 142, 184, 24>>, type: :private}
      iex> Cryptopunk.Crypto.Bitcoin.legacy_address(private_key, :mainnet, uncompressed: true)
      "1AqWUNX6mdaiPay55BqZcAMqNSEJgcgj1D"
  """
  @spec legacy_address(Key.t(), atom() | non_neg_integer(), Keyword.t()) :: String.t()
  def legacy_address(private_or_public_key, net_or_version_byte, opts \\ []) do
    address(private_or_public_key, net_or_version_byte, :legacy, opts)
  end

  @doc """
  Generate a 'Pay to Witness Public Key Hash nested in BIP16 Pay to Script Hash' (P2WPKH-P2SH) address

  It accepts two parameters:

  - public or private key. if a private key is provided, it will be converted to public key.
  - network (`:mainnet` or `:testnet`)

  Examples:

      iex> private_key = %Cryptopunk.Key{key: <<16, 42, 130, 92, 247, 244, 62, 96, 24, 129, 187, 141, 124, 42, 176, 116, 234, 171, 184, 107, 3, 229, 255, 72, 30, 116, 79, 243, 36, 142, 184, 24>>, type: :private}
      iex> Cryptopunk.Crypto.Bitcoin.p2sh_p2wpkh_address(private_key, :mainnet)
      "397Y4wveZFbdEo8rTzXSPHWYuamfKs2GWd"

      iex> public_key = %Cryptopunk.Key{key: <<4, 57, 163, 96, 19, 48, 21, 151, 218, 239, 65, 251, 229, 147, 160, 44, 197, 19, 208, 181, 85, 39, 236, 45, 241, 5, 14, 46, 143, 244, 156, 133, 194, 60, 190, 125, 237, 14, 124, 230, 165, 148, 137, 107, 143, 98, 136, 143, 219, 197, 200, 130, 19, 5, 226, 234, 66, 191, 1, 227, 115, 0, 17, 98, 129>>, type: :public}
      iex> Cryptopunk.Crypto.Bitcoin.p2sh_p2wpkh_address(public_key, :testnet)
      "2NFNttcoWjE7WUcByBqpPKkcjg8wzgnU5HE"
  """
  @spec p2sh_p2wpkh_address(Key.t(), atom() | non_neg_integer()) :: String.t()
  def p2sh_p2wpkh_address(private_or_public_key, net_or_version_byte) do
    address(private_or_public_key, net_or_version_byte, :p2sh_p2wpkh)
  end

  @doc """
  Generate a bech32 segwit address

  It accepts three parameters:

  - public or private key. if a private key is provided, it will be converted to public key.
  - network (`:mainnet`, `:testnet` or `:regtest`)
  - optional parameters. Currently the only allowed parameter is a witness version (`:version`).

  Examples:

      iex> private_key = %Cryptopunk.Key{key: <<16, 42, 130, 92, 247, 244, 62, 96, 24, 129, 187, 141, 124, 42, 176, 116, 234, 171, 184, 107, 3, 229, 255, 72, 30, 116, 79, 243, 36, 142, 184, 24>>, type: :private}
      iex> Cryptopunk.Crypto.Bitcoin.bech32_address(private_key, :mainnet)
      "bc1qc89hn5kmwxl804yfqmd97st3trarqr24y2hpqh"

      iex> private_key = %Cryptopunk.Key{key: <<16, 42, 130, 92, 247, 244, 62, 96, 24, 129, 187, 141, 124, 42, 176, 116, 234, 171, 184, 107, 3, 229, 255, 72, 30, 116, 79, 243, 36, 142, 184, 24>>, type: :private}
      iex> Cryptopunk.Crypto.Bitcoin.bech32_address(private_key, :mainnet, version: 1)
      "bc1pc89hn5kmwxl804yfqmd97st3trarqr246gsxg7"

      iex> public_key = %Cryptopunk.Key{key: <<4, 57, 163, 96, 19, 48, 21, 151, 218, 239, 65, 251, 229, 147, 160, 44, 197, 19, 208, 181, 85, 39, 236, 45, 241, 5, 14, 46, 143, 244, 156, 133, 194, 60, 190, 125, 237, 14, 124, 230, 165, 148, 137, 107, 143, 98, 136, 143, 219, 197, 200, 130, 19, 5, 226, 234, 66, 191, 1, 227, 115, 0, 17, 98, 129>>, type: :public}
      iex> Cryptopunk.Crypto.Bitcoin.bech32_address(public_key, :testnet)
      "tb1qx3ppj0smkuy3d6g525sh9n2w9k7fm7q3vh5ssm"
  """
  @spec bech32_address(Key.t(), atom() | String.t(), Keyword.t()) :: String.t()
  def bech32_address(private_or_public_key, net_or_hrp, opts \\ []) do
    address(private_or_public_key, net_or_hrp, :bech32, opts)
  end

  @spec validate(binary()) :: {:ok, map()} | {:error, atom()}
  def validate(address) do
    maybe_bech32? =
      Enum.any?(Bech32Address.prefixes(), fn prefix ->
        String.starts_with?(address, prefix)
      end)

    if maybe_bech32? do
      Bech32Address.validate(address)
    else
      with {:ok, <<version::8, _data::binary-20>>} <-
             ExBase58.decode_check(address, :bitcoin),
           {:ok, _} <- ExBase58.decode_check_version(address, version, :bitcoin),
           {network, type} <- Map.get(network_versions(), version) do
        {:ok, %{network: network, type: type}}
      else
        _error -> {:error, :invalid_address}
      end
    end
  end

  defp network_versions do
    legacy_versions =
      Map.new(LegacyAddress.version_bytes(), fn {network, version} ->
        {version, {network, :p2pkh}}
      end)

    p2sh_versions =
      Map.new(P2shP2wpkhAddress.version_bytes(), fn {network, version} ->
        {version, {network, :p2sh}}
      end)

    Map.merge(legacy_versions, p2sh_versions)
  end

  defp address(private_key, net_or_version_byte, type, opts \\ [])

  defp address(%Key{type: :private} = private_key, net_or_version_byte, type, opts) do
    private_key
    |> Key.public_from_private()
    |> generate_address(net_or_version_byte, type, opts)
  end

  defp address(%Key{type: :public} = public_key, net_or_version_byte, type, opts) do
    generate_address(public_key, net_or_version_byte, type, opts)
  end

  defp generate_address(public_key, net_or_version_byte, :legacy, opts) do
    LegacyAddress.address(public_key, net_or_version_byte, opts)
  end

  defp generate_address(public_key, net_or_version_byte, :p2sh_p2wpkh, _opts) do
    P2shP2wpkhAddress.address(public_key, net_or_version_byte)
  end

  defp generate_address(public_key, net_or_hrp, :bech32, opts) do
    Bech32Address.address(public_key, net_or_hrp, opts)
  end
end
