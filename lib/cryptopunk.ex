defmodule Cryptopunk do
  @moduledoc """
  Hierarchical deterministic wallet. It has the following features:

  - Generate mnemonic
  - Generate seed from mnemonic
  - Generate master keys from seed
  - Derive private and public keys from the master key
  - Various utility functions to work with derivation path, keys, crypto addresses

  """

  alias Cryptopunk.Derivation
  alias Cryptopunk.Derivation.Path
  alias Cryptopunk.Key
  alias Cryptopunk.Seed

  @doc """
  Generate a mnemonic with the given number of words (24 by default).
  See https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki

  Examples:

      iex> mnemonic1 = Cryptopunk.create_mnemonic()
      iex> mnemonic2 = Cryptopunk.create_mnemonic()
      iex> mnemonic1 |> String.split(" ") |> Enum.count()
      24
      iex> mnemonic1 != mnemonic2
      true
  """
  @spec create_mnemonic(non_neg_integer()) :: String.t() | no_return
  def create_mnemonic(word_number \\ 24), do: Mnemoniac.create_mnemonic!(word_number)

  @doc """
  Generate mnemonic from entropy.

  Examples:

      iex> bytes = <<6, 197, 169, 93, 98, 210, 82, 216, 148, 177, 1, 251, 142, 15, 154, 85, 140, 0, 13, 202, 234, 160, 129, 218>>
      iex> Cryptopunk.create_mnemonic_from_entropy(bytes)
      "almost coil firm shield cement hobby fan cage wine idea track prison scale alone close favorite limb still"
  """
  @spec create_mnemonic_from_entropy(binary()) :: String.t() | no_return
  def create_mnemonic_from_entropy(entropy), do: Mnemoniac.create_mnemonic_from_entropy!(entropy)

  @doc """
  Generate seed from mnemonic.
  See https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki#from-mnemonic-to-seed

  Examples:

      iex> mnemonic = "almost coil firm shield cement hobby fan cage wine idea track prison scale alone close favorite limb still"
      iex> Cryptopunk.create_seed(mnemonic)
      <<180, 208, 65, 58, 208, 96, 16, 14, 214, 63, 190, 54, 77, 169, 17, 207, 191, 239, 227, 252, 200, 195, 135, 251, 68, 70, 169, 124, 100, 147, 143, 61, 26,  196, 128, 18, 245, 89, 94, 32, 11, 35, 71, 132, 156, 123, 140, 123, 114, 55,  72, 40, 57, 245, 153, 249, 124, 98, 130, 203, 108, 168, 109, 144>>
  """
  @spec create_seed(String.t(), binary()) :: binary() | no_return()
  def create_seed(mnemonic, password \\ ""), do: Seed.create(mnemonic, password)

  @doc """
  Generate master private key from seed
  See https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#master-key-generation

  Examples:

      iex> seed = <<98, 235, 236, 246, 19, 205, 197, 254, 187, 41, 62, 19, 189, 20, 24, 73, 206, 187, 198, 83, 160, 138, 77, 155, 195, 97, 140, 111, 133, 102, 241, 26, 176, 95, 206, 198, 71, 251, 118, 115, 134, 215, 226, 194, 62, 106, 255, 94, 15, 142, 227, 186, 152, 88, 218, 220, 184, 63, 242, 30, 162, 59, 32, 229>>
      iex> Cryptopunk.master_key_from_seed(seed)
      %Cryptopunk.Key{
         chain_code:
           <<153, 249, 145, 92, 65, 77, 50, 249, 120, 90, 178, 30, 41, 27, 73, 128, 74, 201,
             91, 250, 143, 238, 129, 247, 115, 87, 161, 107, 123, 63, 84, 243>>,
         key:
           <<50, 8, 92, 222, 223, 155, 132, 50, 53, 227, 114, 79, 88, 11, 248, 24, 239, 76,
             236, 39, 195, 198, 112, 133, 224, 41, 65, 138, 91, 47, 111, 43>>,
         type: :private,
         depth: 0,
         parent_fingerprint: <<0, 0, 0, 0>>,
         index: 0
       }
  """
  @spec master_key_from_seed(binary()) :: Key.t()
  def master_key_from_seed(seed), do: Key.master_key(seed)

  @doc """
  Serialize extended key
  See https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#Serialization_format

  Examples:

      iex> seed = <<98, 235, 236, 246, 19, 205, 197, 254, 187, 41, 62, 19, 189, 20, 24, 73, 206, 187, 198, 83, 160, 138, 77, 155, 195, 97, 140, 111, 133, 102, 241, 26, 176, 95, 206, 198, 71, 251, 118, 115, 134, 215, 226, 194, 62, 106, 255, 94, 15, 142, 227, 186, 152, 88, 218, 220, 184, 63, 242, 30, 162, 59, 32, 229>>
      iex> seed |> Cryptopunk.master_key_from_seed() |> Cryptopunk.serialize_key(<<4, 136, 173, 228>>)
      "xprv9s21ZrQH143K3bGcMmWrLU2jguNt5HPuMcuW2ZSTmHWPecUNW1hZgfyGyTLZYEALk46YzbEiPL7v3s2SDxgdbhHF7SiKiMAz4kVx9u5gfr9"
  """
  @spec serialize_key(Key.t(), binary()) :: String.t()
  def serialize_key(key, version), do: Key.serialize(key, version)

  @doc """
  Deserialize extended key

  Examples:

      iex>  Cryptopunk.deserialize_key("xprv9s21ZrQH143K3bGcMmWrLU2jguNt5HPuMcuW2ZSTmHWPecUNW1hZgfyGyTLZYEALk46YzbEiPL7v3s2SDxgdbhHF7SiKiMAz4kVx9u5gfr9")
      %Cryptopunk.Key{chain_code: <<153, 249, 145, 92, 65, 77, 50, 249, 120, 90, 178, 30, 41, 27, 73, 128, 74, 201, 91, 250, 143, 238, 129, 247, 115, 87, 161, 107, 123, 63, 84, 243>>, depth: 0, index: 0, key: <<50, 8, 92, 222, 223, 155, 132, 50, 53, 227, 114, 79, 88, 11, 248, 24, 239, 76, 236, 39, 195, 198, 112, 133, 224, 41, 65, 138, 91, 47, 111, 43>>, parent_fingerprint: <<0, 0, 0, 0>>, type: :private}
  """
  @spec deserialize_key(binary()) :: Key.t()
  def deserialize_key(key), do: Key.deserialize(key)

  @doc """
  Derives key
  https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki

  Examples:

      iex> seed = <<98, 235, 236, 246, 19, 205, 197, 254, 187, 41, 62, 19, 189, 20, 24, 73, 206, 187, 198, 83, 160, 138, 77, 155, 195, 97, 140, 111, 133, 102, 241, 26, 176, 95, 206, 198, 71, 251, 118, 115, 134, 215, 226, 194, 62, 106, 255, 94, 15, 142, 227, 186, 152, 88, 218, 220, 184, 63, 242, 30, 162, 59, 32, 229>>
      iex> {:ok, path} = Cryptopunk.parse_path("m / 44' / 0' / 0' / 0 / 0")
      iex> seed |> Cryptopunk.master_key_from_seed() |> Cryptopunk.derive_key(path)
      %Cryptopunk.Key{chain_code: <<166, 125, 2, 213, 77, 88, 124, 145, 241, 251, 83, 163, 21, 11, 20, 34, 158, 157, 179, 147, 162, 212, 148, 89, 28, 92, 68, 126, 215, 79, 147, 159>>, depth: 5, index: 0, key: <<214, 231, 94, 203, 167, 219, 125, 43, 251, 91, 147, 51, 32, 146, 186, 215, 58, 45, 104, 58, 119, 114, 121, 238, 155, 215, 239, 189, 37, 236, 27, 70>>, parent_fingerprint: <<205, 94, 166, 92>>, type: :private}
  """
  @spec derive_key(Key.t(), Path.t() | Path.raw_path()) :: Key.t()
  def derive_key(key, path), do: Derivation.derive(key, path)

  @doc """
  Parse derivation path
  See https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki

  Examples:

      iex> Cryptopunk.parse_path("m / 44' / 0' / 0' / 0 / 0")
      {:ok, %Cryptopunk.Derivation.Path{account: 0, address_index: 0, change: 0, coin_type: 0, purpose: 44, type: :private}}
  """
  @spec parse_path(String.t()) :: {:error, any()} | {:ok, Path.t()}
  def parse_path(path), do: Path.parse(path)
end
