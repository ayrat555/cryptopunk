defmodule Cryptopunk.B58 do
  @moduledoc """
  This module provides Base58 and Base58Check data encoding and decoding functions.

  The following alphabets are supported for encoding and decoding, for both Base58 and Base58Check:

    * `Bitcoin`
    * `Flickr`
    * `Ripple`

    Note that `IPFS` uses the same alphabet as Bitcoin. Since this alphabet appeared in Bitcoin first, it will be referred to hereafter as Bitcoin, though it can be used for encoding and decoding data from IPFS without issue.

  ## Overview

  Base58 is a Base58 and Base58Check library that tries to make pragmatic compromises, while maintaining best practices with regard to Elixir and BEAM performance. It has no external dependencies and supports adding additional values with a simple update of an internal map.

  Additionally, Cryptopunk.B58 encodes and decodes data in a consistent manner - plain binary in, plain binary out. No additional steps, clever hacks, or assumptions are made with regard to input and output. Furthermore, the library is relatively consistent with the approach taken in the Elixir core `Base` library.

  In cases where exceptions may be more common, `!` suffixed functions are provided, ex: `base58_decode` vs `base58_decode!`.

  Base58Check data also supports two versions of encoding and decoding respectively. Version binaries are assumed to be input and output via functions prefixed with `version`, ex: `version_encode58_check!/2`. A versioned binary can also be created using `version_binary/2`. Version arguments are also consistently arranged so that they may be easily piped using Elixir. Unversioned binaries may also be encoded and decoded and simply use the same pattern of functions without the version prefix in the name, ex: `encode58_check!`.

  Ensure that when encoding and decoding, you use the appropriate alphabet. For example, if you encode using the Flickr alphabet, decode using the same alphabet. If you do not control encoding, ensure you know up-front what alphabet is used. Base58 will often decode using the incorrect alphabet without an error, but produce wrong results. Base58Check on the other hand will typically fail up-front due to the checksum being incorrect. It is thus possible, but not advisable to try to brute-force detect the alphabet for Base58Check using the `alphabets/0` function with a `reduce_while/3` function as a last resort.

  Ensure the Erlang "crypto" module is installed. There are some OS distributions that do not include this.

  ## Why Base58 Encoding

  The most compelling reason to use Base58 is if you are using or interfacing any technology that already uses it. This includes various crypto-currencies such as Bitcoin, Blockchain-based experiments, various distributed systems, IPFS, Flickr URLs, and many more.

  Generally, you can also decide to use Base58 if you want an unambiguous encoding that is less prone to errors when read by a human. Moreover, you can use Base58Check when you need to checksum and/or version your data.

  Taken from the original Bitcoin source code:

  ```
  Why base-58 instead of standard base-64 encoding?
    - Don't want 0OIl characters that look the same in some fonts and could be used to create visually identical looking account numbers.
    - A string with non-alphanumeric characters is not as easily accepted as an account number.
    - E-mail usually won't line-break if there's no punctuation to break at.
    - Double-clicking selects the whole number as one word if it's all alphanumeric.
  ```

  ## Base58Check Encoding

  The following features are outlined per the bitcoin wiki regarding Base58Check:

  ```
    * An arbitrarily sized payload.
    * A set of 58 alphanumeric symbols consisting of easily distinguished uppercase and lowercase letters (0OIl are not used)
    * One byte of version/application information. Bitcoin addresses use 0x00 for this byte (future ones may use 0x05).
    * Four bytes (32 bits) of SHA256-based error checking code. This code can be used to automatically detect and possibly correct typographical errors.
    * An extra step for preservation of leading zeroes in the data.

  ## Base58Check vs Base58 Encoding

  You should use Base58Check over Base58 encoding if any of the features it presents are appealing to you. Perhaps the most compelling reason to use Base58Check, however, is the ability to version data and embed a checksum.

  Generally, Base58 should perform better as Base58Check is a layer on top of Base58. The checksum in Base58Check, however, will usually prevent accidental decoding using the wrong alphabet.

  ```

  ## Why Not Base58 or Base58Check

  Base58 and Base58Check are suitable and desirable for many reasons ranging from protection from character ambiguity to checksums to real-world software usage. Nevertheless, there are several considerations you should evaluate before selecting Base58 or Base58Check.

  Among the reasons not to use Base58 or Base58Check include:

    * Speed
      * Usage of `div` and `mod`. Both these operations are slow, especially in Elixir. Many other encodings are not performance limited by these operations and thus faster.
      * It may be possible to gain more speed using a technique where div and mod (divmod) together are replaced with a CRC + table approach to avoid the overhead. This is more readily doable in C or C++. It is not clear whether doing this in Elixir has benefits nor if it is worth it in terms of stability and performance doing so via a NIF.
      * Base58Check introduces additional overhead via sha-256, extra binary manipulation, and checksum verification during decoding.
    * Dynamic alphabets
      * Base58 is not as amenable to dynamic alphabets. This library also intentionally ignores this constraint. The main reason is that there are some characters that are counter to the goals of Base58.
      * Losing performance to support a dynamic alphabet is probably not a tradeoff you should be making. Note that dynamic alphabets that follow the guidelines of existing alphabets can be added with a simple compile-time updates of this library.
    * Payload size
      * Some encodings may produce a smaller payload size relative to the source data.
      * You can compress a Base58 payload, but it is not an inherent goal of the algorithm itself.

  ## Selecting an Alphabet

  You should select an alphabet that aligns with your inteded use-cases. If in doubt, start with the bitcoin (`:btc`) alphabet. For usage with URLs such as shorteners or parameters, the Flickr (`:flickr`) alphabet has seen some real-world usage and is thus worth considering.

  If you need to add an alphabet, it is suggested to do so at compile time by updating the `alphabet_meta` map found in the source. It is strongly advised to use an existing alphabet, however.

  ## Base58 Bitcoin Alphabet

      | Value | Encoding | Value | Encoding | Value | Encoding | Value | Encoding |
      |------:|---------:|------:|---------:|------:|---------:|------:|---------:|
      |      0|         1|     17|         J|     34|         b|     51|         t|
      |      1|         2|     18|         K|     35|         c|     52|         u|
      |      2|         3|     19|         L|     36|         d|     53|         v|
      |      3|         4|     20|         M|     37|         e|     54|         w|
      |      4|         5|     21|         N|     38|         f|     55|         x|
      |      5|         6|     22|         P|     39|         g|     56|         y|
      |      6|         7|     23|         Q|     40|         h|     57|         z|
      |      7|         8|     24|         R|     41|         i|       |          |
      |      8|         9|     25|         S|     42|         j|       |          |
      |      9|         A|     26|         T|     43|         k|       |          |
      |     10|         B|     27|         U|     44|         m|       |          |
      |     11|         C|     28|         V|     45|         n|       |          |
      |     12|         D|     29|         W|     46|         o|       |          |
      |     13|         E|     30|         X|     47|         p|       |          |
      |     14|         F|     31|         Y|     48|         q|       |          |
      |     15|         G|     32|         Z|     49|         r|       |          |
      |     16|         H|     33|         a|     50|         s|       |          |

  ## Base58 Flickr Alphabet

      | Value | Encoding | Value | Encoding | Value | Encoding | Value | Encoding |
      |------:|---------:|------:|---------:|------:|---------:|------:|---------:|
      |      0|         1|     17|         i|     34|         A|     51|         T|
      |      1|         2|     18|         j|     35|         B|     52|         U|
      |      2|         3|     19|         k|     36|         C|     53|         V|
      |      3|         4|     20|         m|     37|         D|     54|         W|
      |      4|         5|     21|         n|     38|         E|     55|         X|
      |      5|         6|     22|         o|     39|         F|     56|         Y|
      |      6|         7|     23|         p|     40|         G|     57|         Z|
      |      7|         8|     24|         q|     41|         H|       |          |
      |      8|         9|     25|         r|     42|         J|       |          |
      |      9|         a|     26|         s|     43|         K|       |          |
      |     10|         b|     27|         t|     44|         L|       |          |
      |     11|         c|     28|         u|     45|         M|       |          |
      |     12|         d|     29|         v|     46|         N|       |          |
      |     13|         e|     30|         w|     47|         P|       |          |
      |     14|         f|     31|         x|     48|         Q|       |          |
      |     15|         g|     32|         y|     49|         R|       |          |
      |     16|         h|     33|         z|     50|         S|       |          |

  ## Base58 Ripple Alphabet

      | Value | Encoding | Value | Encoding | Value | Encoding | Value | Encoding |
      |------:|---------:|------:|---------:|------:|---------:|------:|---------:|
      |      0|         r|     17|         J|     34|         b|     51|         t|
      |      1|         p|     18|         K|     35|         c|     52|         u|
      |      2|         s|     19|         L|     36|         d|     53|         v|
      |      3|         h|     20|         M|     37|         e|     54|         A|
      |      4|         n|     21|         4|     38|         C|     55|         x|
      |      5|         a|     22|         P|     39|         g|     56|         y|
      |      6|         f|     23|         Q|     40|         6|     57|         z|
      |      7|         3|     24|         R|     41|         5|       |          |
      |      8|         9|     25|         S|     42|         j|       |          |
      |      9|         w|     26|         T|     43|         k|       |          |
      |     10|         B|     27|         7|     44|         m|       |          |
      |     11|         U|     28|         V|     45|         8|       |          |
      |     12|         D|     29|         W|     46|         o|       |          |
      |     13|         N|     30|         X|     47|         F|       |          |
      |     14|         E|     31|         Y|     48|         q|       |          |
      |     15|         G|     32|         Z|     49|         i|       |          |
      |     16|         H|     33|         2|     50|         1|       |          |

  ## References

    * [Base58](https://en.wikipedia.org/wiki/Base58)
    * [Base58Check](https://en.bitcoin.it/wiki/Base58Check_encoding)
    * [Base58 Flickr](https://www.flickr.com/groups/51035612836@N01/discuss/72157616713786392/)
    * [Elixir Base Module](https://github.com/elixir-lang/elixir/blob/master/lib/elixir/lib/base.ex)
    * [Ripple Github](https://github.com/ripple)
    * [Bitcoin Base58 Implementation](https://github.com/bitcoin/bitcoin/blob/master/src/base58.cpp)
    * [Erlang Crypto Module](http://erlang.org/doc/man/crypto.html)

  """

  # note that each of these alphabets is a charlist, not a binary!
  b58_btc_alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
  b58_flickr_alphabet = '123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ'
  b58_ripple_alphabet = 'rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz'

  # you can add more alphabets here. alphabets are kept in a specific order here intentionally.
  alphabet_meta = [
    %{alphabet_id: :btc, alphabet: b58_btc_alphabet},
    %{alphabet_id: :flickr, alphabet: b58_flickr_alphabet},
    %{alphabet_id: :ripple, alphabet: b58_ripple_alphabet}
  ]

  @typedoc """
  1-byte version binary
  """
  @type version :: <<_::8>>

  @typedoc """
  Unsigned single-byte integer (unint8 commonly)
  """
  @type version_integer :: 0..255

  @typedoc """
  A binary where the first byte is assumed to be a version.
  """
  @type versioned_binary :: <<_::8, _::_*8>>

  @typedoc """
  A Base58 encoded binary.
  """
  @type b58_binary :: binary()

  @typedoc """
  A Base58Check encoded binary
  """
  @type b58check_binary() :: <<_::48, _::_*8>>

  @typedoc """
  An alphabet ID atom that corresponds to the intended alphabet to be used for encoding or decoding.
  """
  @type alphabet :: :btc | :flickr | :ripple

  # A word about errors:
  # ============================================================================
  # We raise usually in this module because we're optimizing for the case of correct values for encoding and decoding.
  # Introducing tuples everywhere adds some GC churn and extra memory when all is well no matter what.
  # Rather than converting {:ok, result} into result or duping code, we simply rescue for now.
  # The other big reason this is done is to be somewhat consistent with the behavior of the Elixir `Base` library.
  # Raising is certainly less desirable than some alternatives, but we follow the core library's approach.
  # If someone has a concern about this or really needs it a different way, it would be easy enough to refactor most of the code here.
  # Stuffing some more code into private functions would help this effort, but I'm less of a fan of this unless necessary.
  # Personally, I do prefer an {:error, reason} approach, especially when atoms can be a reason to pattern match against.,
  # The main case where I feel there is some benefit here is when dealing with checksums errors in Base58Check. In that case I would prefer {:error, :invalid_checksum}.
  # We could manipulate the rescue body to do some of this by raising more specific errors, but I'm not sure there is a demand for this and it introduces yet more code.

  @doc """
  Encodes a binary in Base58.

  ## Examples

      iex> Cryptopunk.B58.encode58("Some chicken is better than no chicken")
      "DLrwGKtrzZkxaLwqpwBBbkgFiEGTYhhzEpjXuj5R2DZPGzbXfeVK"

      iex> Cryptopunk.B58.encode58("Some chicken is better than no chicken", alphabet: :btc)
      "DLrwGKtrzZkxaLwqpwBBbkgFiEGTYhhzEpjXuj5R2DZPGzbXfeVK"

      iex> Cryptopunk.B58.encode58("The T in Tacos stands for terrific", alphabet: :flickr)
      "2UF2YLgW2MQSutxJWpcW6afxo1YbVm4ZnXociLQ1eExXRwK"

      iex> "536D656C6C73206C696B652061206C6F636B657220726F6F6D20696E2068657265" |> Base.decode16!() |> Cryptopunk.B58.encode58(alphabet: :ripple)
      "R8RKuNXBxzb1Ai6HrP3mHmgyBEKmWjp944zS4Y9Q7hsPS"

  """
  @spec encode58(binary(), keyword()) :: b58_binary()
  def encode58(data, opts \\ []) when is_binary(data) do
    alphabet = Keyword.get(opts, :alphabet, :btc)
    do_encode58(data, alphabet)
  end

  @doc """
  Encodes a binary in Base58Check using the given version byte.

  ## Examples

      iex> Cryptopunk.B58.encode58_check!("Lost my sauce, sorry boss.", 0)
      "1GKJd5qu8gaFbd4tHVPF6q8ZtzER5ttJSwLTN2A5MT"

      iex> Cryptopunk.B58.encode58_check!("Lost my sauce, sorry boss.", 1, alphabet: :btc)
      "29cSfWnUdLoFyrRquaF4fQ2xnKSMg8TWenhe89Mc95"

      iex> Cryptopunk.B58.encode58_check!("Lettuceless Burritos", "m", alphabet: :ripple)
      "kyo6DdGZMd7yc1EmNVz2jh4sEc3qUNBY1D"

      iex> "466F6F20426172204578616D706C657320617265207265616C6C792064616D6E20737475706964" |> Base.decode16!() |> Cryptopunk.B58.encode58_check!("2", alphabet: :flickr)
      "hm63nMd9884zRLqGD2cYDUgk3JR1EEEbP6UQfEU2uPAoZfQe3VrXHfYvRkok"

  """
  @spec encode58_check!(binary(), version | version_integer(), keyword()) :: b58check_binary()
  def encode58_check!(data, version, opts \\ []) do
    version_binary(data, version) |> do_encode58_check(opts)
  end

  @doc """
  Encodes a binary in Base58Check using the given version byte.

  ## Examples

      iex> Cryptopunk.B58.encode58_check("So Afraid of failure", <<1>>, alphabet: :btc)
      {:ok, "XwmCCcWGbEjGsJk4THsxw28EcQuz6TYyu"}

      iex> Cryptopunk.B58.encode58_check("Incapable coworker lacking understanding what a byte is", <<1, 2>>, alphabet: :btc)
      {:error,
      "version must be a single byte binary or unsigned integer, data must be a binary."}

  """
  @spec encode58_check(binary(), version | version_integer(), keyword()) ::
          {:ok, b58check_binary()} | {:error, term()}
  def encode58_check(data, version, opts \\ []) do
    {:ok, encode58_check!(data, version, opts)}
  rescue
    e in _ -> {:error, Exception.message(e)}
  end

  @doc """
  Encodes a binary in Base58Check using the first byte as the version byte. Assumes the binary is already versioned.

  ## Examples

      iex> Cryptopunk.B58.version_encode58_check!(<<5, "256 versions ought to be enough for anyone">>)
      "3WGnVcRSYcejzu1tmjqG36i8zGFhPH5v7399paTXYSvCQPRsqSa86CcnRUPVJxXw"

      iex> Cryptopunk.B58.version_encode58_check!("1Mad Lad", alphabet: :ripple)
      "vx82hmfYGg4kdDK5"

      iex> Cryptopunk.B58.version_encode58_check!(<<255, "Push the limits until the car starts">>, alphabet: :flickr)
      "XZABbyyTLAtpXB4uyan6stxnyFhPH2kbr1v6j26SBAvDqrQi8GGBDKxs"

  """
  @spec version_encode58_check!(versioned_binary(), keyword()) :: b58check_binary()
  def version_encode58_check!(versioned_data, opts \\ []) do
    do_encode58_check(versioned_data, opts)
  end

  @doc """
  Encodes a binary in Base58Check using the first byte as the version byte. Assumes the binary is already versioned.

  ## Examples

      iex> Cryptopunk.B58.version_encode58_check(<<5, "256 versions ought to be enough for anyone">>)
      {:ok, "3WGnVcRSYcejzu1tmjqG36i8zGFhPH5v7399paTXYSvCQPRsqSa86CcnRUPVJxXw"}

      iex> Cryptopunk.B58.version_encode58_check("1Mad Lad", alphabet: :ripple)
      {:ok, "vx82hmfYGg4kdDK5"}

      iex> Cryptopunk.B58.version_encode58_check(<<255, "Push the limits until the car starts">>, alphabet: :flickr)
      {:ok, "XZABbyyTLAtpXB4uyan6stxnyFhPH2kbr1v6j26SBAvDqrQi8GGBDKxs"}

  """
  @spec version_encode58_check(versioned_binary(), keyword()) ::
          {:ok, b58check_binary()} | {:error, term()}
  def version_encode58_check(versioned_data, opts \\ []) do
    {:ok, do_encode58_check(versioned_data, opts)}
  rescue
    e in _ -> {:error, Exception.message(e)}
  end

  @doc """
  Decodes a Base58 binary.

  An `ArgumentError` exception is raised if the binary contains characters that are invalid for the given alphabet.

  ## Examples

      iex> Cryptopunk.B58.decode58!("59QpGHkaSK8tngYpe9h17cseyAEGc")
      "Cheese Platter Please"

      iex> Cryptopunk.B58.decode58!("asDvaq68ktFaubY7KsnvBFMMD5Q8cd9PhGma3YcPqoWXX2aJoiaK1kc65gn", alphabet: :ripple)
      "Decode using the alphabet it was encoded in"

      iex> Cryptopunk.B58.decode58!("2zPJuvDvDNbavb7zdUVM9niBSHNTjPni85f8hPLJ119awVLKud3kWU5LsRGiqkzav8wD6MFj2QshN3b8SyTEpkG2pYcSAioeUUDe6wqhigji4vkBVQoBJ9mPLmySgjQyy8FrYu3rd", alphabet: :btc) |> Base.decode16!()
      "0088C2D2FA846282C870A76CADECBE45C4ACD72BB655DA1216"

  """
  @spec decode58!(b58_binary(), keyword()) :: b58_binary()
  def decode58!(string, opts \\ []) when is_binary(string) do
    alphabet = Keyword.get(opts, :alphabet, :btc)
    do_decode58(string, alphabet)
  end

  @doc """
  Decodes a Base58 binary.

  An `{:error, reason}` tuple is returned if the binary contains characters that are invalid for the given alphabet.

  ## Examples

      iex> Cryptopunk.B58.decode58("59QpGHkaSK8tngYpe9h17cseyAEGc", alphabet: :btc)
      {:ok, "Cheese Platter Please"}

      iex> Cryptopunk.B58.decode58("2nePN7syqoQe2mfeY", alphabet: :flickr)
      {:ok, "Hello Sailor"}

      iex> Cryptopunk.B58.decode58("02nePN7syqoQe2mfeY", alphabet: :flickr)
      {:error, "non-alphabet digit found: \\"0\\" (byte 48)"}

  """
  @spec decode58(b58_binary(), keyword()) :: {:ok, b58_binary()} | {:error, term()}
  def decode58(string, opts \\ []) when is_binary(string) do
    {:ok, decode58!(string, opts)}
  rescue
    e in _ -> {:error, Exception.message(e)}
  end

  @doc """
  Decodes a Base58Check binary.

  An `ArgumentError` exception is raised if the binary contains characters that are invalid for the given alphabet or if the checksum bytes do not match the payload.

  ## Examples

      iex> Cryptopunk.B58.decode58_check!("12nwcb8vmxv3waEzzPtaY3XBmWbwvGvqw", alphabet: :flickr)
      {"Backstrom for Selke", <<0>>}

      iex> Cryptopunk.B58.decode58_check!("ftyYJFWLdZWzNfyFqPGXGpxM6aFNnTkqmz1QwcoT3eQAQPb9V4bRQScejwWQWTR8", alphabet: :ripple)
      {"No one wants to play Sega Genesis with you", <<14>>}

      iex> Cryptopunk.B58.decode58_check!("2mzYnhGdFMacGVTrvyZsnqDGPqWFefouMQA")
      {<<245, 74, 88, 81, 233, 55, 43, 135, 129, 10, 142, 96, 205, 210, 231, 207, 216,
      11, 110, 49>>, <<255>>}

  """
  @spec decode58_check!(b58check_binary(), keyword()) :: {binary(), version()}
  def decode58_check!(string, opts \\ [])

  def decode58_check!(string, opts) when is_binary(string) and byte_size(string) > 5 do
    decoded_bin = decode58!(string, opts)
    decoded_size = byte_size(decoded_bin)
    payload_size = decoded_size - 5

    <<version::binary-size(1), payload::binary-size(payload_size), checksum::binary-size(4)>> =
      decoded_bin

    if calculate_checksum(<<version::binary-size(1), payload::binary>>) == checksum do
      {payload, version}
    else
      raise ArgumentError, "Invalid checksum."
    end
  end

  def decode58_check!(_string, _opts) do
    # A base 58 string will always be at least 5 bytes due to the version and checksum,
    raise ArgumentError, "Invalid Base58Check string."
  end

  @doc """
  Decodes a Base58Check binary.

  An `{:error, reason}` tuple is returned if the binary contains characters that are invalid for the given alphabet or if the checksum bytes do not match the payload.

  ## Examples

      iex> Cryptopunk.B58.decode58_check("QGgq7M6oMmgLQiWY9SUgo5QoaK6FH44nM")
      {:ok, {"Backstrom for Selke", <<255>>}}

      iex> Cryptopunk.B58.decode58_check!("17B1aKcMUBrrX9t6Y7ZUSkDoedGLiybgnJ", alphabet: :flickr)
      {"Hot Delicious Treats", <<0>>}

      iex> Cryptopunk.B58.decode58_check("QGgq7M6oMmgLQiWY9SUgo5QoaK6FH44n_", alphabet: :btc)
      {:error, "non-alphabet digit found: \\"_\\" (byte 95)"}

      iex> Cryptopunk.B58.decode58_check("QGgq7M6oMmgLQiWY9SUgo5QoaK6FH44nM", alphabet: :ripple)
      {:error, "Invalid checksum."}

  """
  @spec decode58_check(b58check_binary(), keyword()) ::
          {:ok, {binary(), version()}} | {:error, term()}
  def decode58_check(string, opts \\ []) when is_binary(string) do
    {:ok, decode58_check!(string, opts)}
  rescue
    e in _ -> {:error, Exception.message(e)}
  end

  @doc """
  Decodes a Base58Check binary with the version byte included in the returned binary.

  An `ArgumentError` exception is raised if the binary contains characters that are invalid for the given alphabet or if the checksum bytes do not match the payload.

  ## Examples

      iex> Cryptopunk.B58.version_decode58_check!("2XLgTmqxf6wu4zAwBAb2hvezGWht")
      "mSeal of Quality"

      iex> Cryptopunk.B58.version_decode58_check!("5XtVTWqqaYj7VUodxQwwgnioaGCoB1fVFzMSXLfQWBiUmsEfo6oJ73CpJojLDuYa3fFE77uvAax4ctzBT17me", alphabet: :flickr)
      "SEvery library says it is fast. Surely, they are all fast."

      iex> Cryptopunk.B58.version_decode58_check!("YXUaKUi6gkm3DRXp8hDrbB", alphabet: :ripple)
      <<255, 66, 114, 111, 103, 114, 97, 109, 109, 101, 114, 115>>

  """
  @spec version_decode58_check!(b58check_binary(), keyword()) :: versioned_binary()
  def version_decode58_check!(string, opts \\ [])

  def version_decode58_check!(string, opts) when is_binary(string) and byte_size(string) > 5 do
    # Again, intentionally avoiding error tuples and such here
    decoded_bin = decode58!(string, opts)
    decoded_size = byte_size(decoded_bin)
    bin_size = decoded_size - 4

    <<versioned_binary::binary-size(bin_size), checksum::binary-size(4)>> = decoded_bin

    if calculate_checksum(versioned_binary) == checksum do
      versioned_binary
    else
      raise ArgumentError, "Invalid checksum."
    end
  end

  def version_decode58_check!(_string, _opts) do
    raise ArgumentError, "Invalid Base58Check string."
  end

  @doc """
  Decodes a Base58Check binary with the version byte included in the returned binary.

  An `{:error, reason}` tuple is returned if the binary contains characters that are invalid for the given alphabet or if the checksum bytes do not match the payload.

  ## Examples

      iex> Cryptopunk.B58.version_decode58_check("2XLgTmqxf6wu4zAwBAb2hvezGWht")
      {:ok, "mSeal of Quality"}

      iex> Cryptopunk.B58.version_decode58_check("2XLgTmqxf6wu4zAwBAb2hvezGWht", alphabet: :flickr)
      {:error, "Invalid checksum."}

      iex> Cryptopunk.B58.version_decode58_check("2XLgTmqxf6wu4zAwBAb2hvezGWht0", alphabet: :btc)
      {:error, "non-alphabet digit found: \\"0\\" (byte 48)"}

      iex> Cryptopunk.B58.version_decode58_check("2QRkeNpTrYPiooUJjcubi1fprQ7aB8XvxSZ2wa4JQeBryrPVCvvkcY5NkXeptH6UzjKBBznXp58MWv4TTBvSHgeyjwPtY", alphabet: :ripple)
      {:ok,
      <<255, 83, 116, 111, 112, 32, 117, 115, 105, 110, 103, 32, 69, 110, 117, 109,
       46, 97, 116, 32, 116, 111, 32, 108, 111, 111, 107, 117, 112, 32, 116, 104,
       105, 110, 103, 115, 32, 105, 110, 32, 99, 111, 100, 101, 99, 115, 46, 32, 75,
       110, 111, 119, 32, 121, 111, 117, 114, 32, 66, 105, 103, 32, 79, 46>>}

  """
  @spec version_decode58_check(b58check_binary(), keyword()) ::
          {:ok, versioned_binary()} | {:error, term()}
  def version_decode58_check(string, opts \\ []) when is_binary(string) do
    {:ok, version_decode58_check!(string, opts)}
  rescue
    e in _ -> {:error, Exception.message(e)}
  end

  @doc """
  Versions a binary according to the Base58Check rules.

  Only use with unversioned binaries.

  An ArgumentError is raised if the version is not a single byte unsigned integer (uint8).

  ## Examples

      iex> Cryptopunk.B58.version_binary("Chicken Recipe", 42)
      "*Chicken Recipe"

      iex> Cryptopunk.B58.version_binary("Chicken Recipe", <<255>>)
      <<255, 67, 104, 105, 99, 107, 101, 110, 32, 82, 101, 99, 105, 112, 101>>

      iex> Cryptopunk.B58.version_binary("Chicken Recipe", <<0>>) |> Cryptopunk.B58.version_encode58_check!()
      "13oALC94NVeHBQsneF6tYRmW4R"

  """
  @spec version_binary(binary(), version | version_integer()) :: versioned_binary()
  def version_binary(data, version)

  def version_binary(data, version)
      when is_binary(data) and is_integer(version) and version >= 0 and version <= 255 do
    <<version::unsigned-integer-size(1)-unit(8), data::binary>>
  end

  def version_binary(data, version)
      when is_binary(data) and is_binary(version) and byte_size(version) == 1 do
    <<version::binary-size(1), data::binary>>
  end

  def version_binary(_data, _version) do
    raise ArgumentError,
          "version must be a single byte binary or unsigned integer, data must be a binary."
  end

  @doc """
  Lists all the alphabets available as identifiers to use with Base58.

  ## Examples

      iex> Cryptopunk.B58.alphabets()
      [:btc, :flickr, :ripple]

  """
  @spec alphabets() :: [alphabet()]
  defmacro alphabets() do
    alphabet_ids =
      Enum.map(unquote(alphabet_meta |> Macro.escape()), fn %{alphabet_id: alphabet_id} ->
        alphabet_id
      end)

    quote do
      unquote(alphabet_ids)
    end
  end

  # ===============================================================================
  # Private eyes, is watching you
  # ===============================================================================

  # ===============================================================================
  # Would prefer to write the following few macros a little bit differently, but leaving this to be semi-consistent with the 'Base' Elixir core library.
  # This code here has been adapted from https://github.com/elixir-lang/elixir/blob/v1.7.3/lib/elixir/lib/base.ex and is somewhat simplified.
  # ===============================================================================
  defmacrop encode_char(alphabet, value) do
    quote do
      case unquote(value) do
        unquote(encode_char_clauses(alphabet))
      end
    end
  end

  defp encode_char_clauses(alphabet) do
    clauses =
      alphabet
      |> Enum.with_index()
      |> encode_clauses()

    clauses ++ bad_digit_clause()
  end

  defp encode_clauses(alphabet) do
    for {encoding, value} <- alphabet do
      [clause] = quote(do: (unquote(value) -> unquote(encoding)))
      clause
    end
  end

  defmacrop decode_char(alphabet, encoding) do
    quote do
      case unquote(encoding) do
        unquote(decode_char_clauses(alphabet))
      end
    end
  end

  defp decode_char_clauses(alphabet) do
    clauses =
      alphabet
      |> Enum.with_index()
      |> decode_clauses()

    clauses ++ bad_digit_clause()
  end

  defp decode_clauses(alphabet) do
    for {encoding, value} <- alphabet do
      [clause] = quote(do: (unquote(encoding) -> unquote(value)))
      clause
    end
  end

  defp bad_digit_clause() do
    quote do
      c ->
        raise ArgumentError,
              "non-alphabet digit found: #{inspect(<<c>>, binaries: :as_strings)} (byte #{c})"
    end
  end

  # ===============================================================================
  # Encoding
  # ===============================================================================
  defp calculate_checksum(versioned_data) do
    <<checksum::binary-size(4), _rest::binary>> =
      :crypto.hash(:sha256, :crypto.hash(:sha256, versioned_data))

    checksum
  end

  defp do_encode58_check(versioned_data, opts) do
    checksum = calculate_checksum(versioned_data)
    encode58(<<versioned_data::binary, checksum::binary-size(4)>>, opts)
  end

  for %{alphabet_id: alphabet_id, alphabet: alphabet} <- alphabet_meta do
    encode_body_fun = :"encode58_#{alphabet_id}_body"
    char_fun = :"encode58_#{alphabet_id}_char"
    prefix_encode_fun = :"prefix_#{alphabet_id}_encode"

    defp unquote(char_fun)(value) do
      encode_char(unquote(alphabet), value)
    end

    defp do_encode58(<<>>, unquote(alphabet_id)) do
      <<>>
    end

    # we proxy this call first to pattern match *once*, not every iteration when recursively decoding
    # this code could be extracted, but with real benchmarks, emitting the same code seemed to perform a bit better than trying to have an extra call to produce a hot path
    # in the future might be worth a slight refactor + bench to see if this changes as new BEAM and Elixir versions are released
    defp do_encode58(data, unquote(alphabet_id)) do
      data
      |> :binary.decode_unsigned()
      |> unquote(encode_body_fun)([])
      |> unquote(prefix_encode_fun)(data)
      |> to_string()
    end

    defp unquote(encode_body_fun)(0, acc) do
      acc
    end

    defp unquote(encode_body_fun)(n, acc) do
      quotient = div(n, 58)
      char = rem(n, 58) |> unquote(char_fun)()
      unquote(encode_body_fun)(quotient, [char | acc])
    end

    defp unquote(prefix_encode_fun)(encoded, <<0, rest::binary>>),
      do: unquote(prefix_encode_fun)([unquote(char_fun)(0) | encoded], rest)

    defp unquote(prefix_encode_fun)(encoded, _data), do: encoded
  end

  # ===============================================================================
  # Decoding
  # ===============================================================================
  defp do_decode58(<<>>, _alphabet_id) do
    <<>>
  end

  defp do_decode58(string, alphabet_id) do
    decode_body(alphabet_id, string)
  end

  for %{alphabet_id: alphabet_id, alphabet: alphabet} <- alphabet_meta do
    decode_body_fun = :"decode58_#{alphabet_id}_body"
    char_fun = :"decode58_#{alphabet_id}_char"
    decode_prefix_fun = :"decode58_#{alphabet_id}_prefix"
    zero_char = Enum.at(alphabet, 0)

    defp unquote(char_fun)(value) do
      decode_char(unquote(alphabet), value)
    end

    defp unquote(decode_body_fun)([], acc) do
      acc |> :binary.encode_unsigned()
    end

    defp unquote(decode_body_fun)([char | remaining_chars], acc) do
      unquote(decode_body_fun)(remaining_chars, acc * 58 + unquote(char_fun)(char))
    end

    defp decode_body(unquote(alphabet_id), string) do
      {remaining_string, leading_zeroes_count} = unquote(decode_prefix_fun)(string, 0)

      body =
        if remaining_string == <<>>,
          do: <<>>,
          else: unquote(decode_body_fun)(to_charlist(remaining_string), 0)

      <<0::size(leading_zeroes_count)-unit(8), body::binary>>
    end

    defp unquote(decode_prefix_fun)(<<unquote(zero_char), rest::binary>>, acc),
      do: unquote(decode_prefix_fun)(rest, acc + 1)

    defp unquote(decode_prefix_fun)(bin, acc), do: {bin, acc}
  end
end
