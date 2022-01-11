defmodule Cryptopunk.B58Test do
  use ExUnit.Case, async: true

  doctest Cryptopunk.B58
  import Cryptopunk.B58

  alias Cryptopunk.B58

  # ============================================================================
  # Defaults
  # ============================================================================
  test "encode58/1 Base58 encodes strings according to the bitcoin alphabet" do
    assert B58.encode58("hello") == "Cn8eVZg"
    assert B58.encode58("hello world") == "StV1DL6CwTryKyV"
    assert B58.encode58("Hello World") == "JxF12TrwUP45BMd"
    assert B58.encode58(<<>>) == <<>>
  end

  test "encode58/1 Base58 encodes sha-256 strings according to the bitcoin alphabet" do
    # From https://github.com/multiformats/multihash
    assert "12209CBC07C3F991725836A3AA2A581CA2029198AA420B9D99BC0E131D9F3E2CBE47"
           |> Base.decode16!()
           |> B58.encode58() == "QmYtUc4iTCbbfVSDNKvtQqrfyezPPnFvE33wFmutw9PBBk"
  end

  test "encode58/1 handles Base58 encoding leading zeroes using the bitcoin alphabet" do
    assert B58.encode58(<<0>>) == "1"
    assert B58.encode58(<<0, 0, 0, "hello world">>) == "111StV1DL6CwTryKyV"
    assert B58.encode58(<<0, 0, 0>>) == "111"
  end

  test "encode58_check!/2 accepts only unsigned single byte integers using the bitcoin alphabet" do
    assert B58.encode58_check!("a", <<0>>) == "1C3t9Nib"
    assert B58.encode58_check!("a", 0) == "1C3t9Nib"
    assert B58.encode58_check!("a", <<1>>) == "gqkwoXD"
    assert B58.encode58_check!("a", 1) == "gqkwoXD"
    assert B58.encode58_check!("a", <<2>>) == "2BkJbhjW"
    assert B58.encode58_check!("a", 2) == "2BkJbhjW"
    assert B58.encode58_check!("a", <<255>>) == "3CAw3RMCe"
    assert B58.encode58_check!("a", 255) == "3CAw3RMCe"
    assert B58.encode58_check!(<<>>, <<2>>) == "Epi3KP"
    assert B58.encode58_check!(<<>>, 2) == "Epi3KP"

    assert_raise ArgumentError, fn ->
      B58.encode58_check!("a", 256)
    end

    assert_raise ArgumentError, fn ->
      B58.encode58_check!("a", -1)
    end

    assert_raise ArgumentError, fn ->
      B58.encode58_check!("a", <<1, 0>>)
    end
  end

  test "encode58_check!/2 Base58Check encodes strings according to the bitcoin alphabet" do
    assert B58.encode58_check!("hello", 0) == "12L5B5yqsf7vwb"
    assert B58.encode58_check!("hello world", 1) == "B5oSH5yUDQS9XwzogrcWP"
    assert B58.encode58_check!("Hello World", 255) == "YXMkDYBSTEWVuE2vQhQ1nc"
    assert B58.encode58_check!(<<>>, 0) == "1Wh4bh"
  end

  test "encode58_check/2 Base58Check encodes strings according to the bitcoin alphabet" do
    assert B58.encode58_check("hello", 0) == {:ok, "12L5B5yqsf7vwb"}
    assert B58.encode58_check("hello world", 1) == {:ok, "B5oSH5yUDQS9XwzogrcWP"}
    assert B58.encode58_check("Hello World", 255) == {:ok, "YXMkDYBSTEWVuE2vQhQ1nc"}
    assert B58.encode58_check(<<>>, 0) == {:ok, "1Wh4bh"}
  end

  test "encode58_check!/2 Base58Check encodes sha-256 strings according to the bitcoin alphabet" do
    # From https://github.com/multiformats/multihash
    assert "12209CBC07C3F991725836A3AA2A581CA2029198AA420B9D99BC0E131D9F3E2CBE47"
           |> Base.decode16!()
           |> B58.encode58_check!(0) == "13gXk986h9pApW3uNeGAHDqUnYHo8c1oSfHajVDuzPtiSokwhzzeK"
  end

  test "encode58_check!/2 Base58Check encodes a RIPEMD-160 hash" do
    # ex per: https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
    assert "f54a5851e9372b87810a8e60cdd2e7cfd80b6e31"
           |> Base.decode16!(case: :lower)
           |> B58.encode58_check!(0) == "1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs"
  end

  test "encode58_check!/1 handles Base58 encoding leading zeroes" do
    assert B58.encode58_check!(<<0>>, 0) == "112edB6q"
    assert B58.encode58_check!(<<0, 0, 0, "hello world">>, 0) == "11113vQB7B6MrGQZaxCrokgx4"
    assert B58.encode58_check!(<<0, 0, 0>>, 0) == "11114bdQda"
  end

  test "version_encode58_check!/2 accepts unsigned single byte integer versions" do
    assert B58.version_encode58_check!(<<0, "a">>) == "1C3t9Nib"
    assert B58.version_encode58_check!(<<1, "a">>) == "gqkwoXD"
    assert B58.version_encode58_check!(<<2, "a">>) == "2BkJbhjW"
    assert B58.version_encode58_check!(<<255, "a">>) == "3CAw3RMCe"
    assert B58.version_encode58_check!(<<2>>) == "Epi3KP"
  end

  test "version_encode58_check!/2 Base58Check encodes strings according to the bitcoin alphabet" do
    assert B58.version_encode58_check!(<<0, "hello">>) == "12L5B5yqsf7vwb"
    assert B58.version_encode58_check!(<<1, "hello world">>) == "B5oSH5yUDQS9XwzogrcWP"
    assert B58.version_encode58_check!(<<255, "Hello World">>) == "YXMkDYBSTEWVuE2vQhQ1nc"
    assert B58.version_encode58_check!(<<0>>) == "1Wh4bh"
  end

  test "version_encode58_check/2 Base58Check encodes strings according to the bitcoin alphabet" do
    assert B58.version_encode58_check(<<0, "hello">>) == {:ok, "12L5B5yqsf7vwb"}
    assert B58.version_encode58_check(<<1, "hello world">>) == {:ok, "B5oSH5yUDQS9XwzogrcWP"}
    assert B58.version_encode58_check(<<255, "Hello World">>) == {:ok, "YXMkDYBSTEWVuE2vQhQ1nc"}
    assert B58.version_encode58_check(<<0>>) == {:ok, "1Wh4bh"}
  end

  test "version_encode58_check!/1 Base58Check encodes a versioned RIPEMD-160 hash" do
    # ex per: https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
    assert 0xF54A5851E9372B87810A8E60CDD2E7CFD80B6E31
           |> :binary.encode_unsigned()
           |> B58.version_binary(0)
           |> B58.version_encode58_check!() == "1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs"
  end

  test "version_encode58_check!/1 handles Base58 encoding leading zeroes" do
    assert B58.version_encode58_check!(<<0, 0>>) == "112edB6q"

    assert B58.version_encode58_check!(<<0, 0, 0, 0, "hello world">>) ==
             "11113vQB7B6MrGQZaxCrokgx4"

    assert B58.version_encode58_check!(<<0, 0, 0, 0>>) == "11114bdQda"
  end

  test "decode58!/1 decodes Base58 encoded binaries using the bitcoin alphabet" do
    assert B58.decode58!("Cn8eVZg") == "hello"
    assert B58.decode58!("StV1DL6CwTryKyV") == "hello world"
    assert B58.decode58!("JxF12TrwUP45BMd") == "Hello World"
    assert B58.decode58!(<<>>) == <<>>
  end

  test "decode58!/1 handles Base58 encoded with leading zeroes using the bitcoin alphabet" do
    assert B58.decode58!("1") == <<0>>
    assert B58.decode58!("111StV1DL6CwTryKyV") == <<0, 0, 0, "hello world">>
    assert B58.decode58!("111") == <<0, 0, 0>>
  end

  test "decode58!/1 Base58 decodes sha-256 strings using the bitcoin alphabet" do
    # From https://github.com/multiformats/multihash
    assert "QmYtUc4iTCbbfVSDNKvtQqrfyezPPnFvE33wFmutw9PBBk"
           |> B58.decode58!()
           |> Base.encode16() ==
             "12209CBC07C3F991725836A3AA2A581CA2029198AA420B9D99BC0E131D9F3E2CBE47"
  end

  test "decode58!/1 Base58 handles invalid binaries when using the bitcoin alphabet" do
    # invalid character
    assert_raise ArgumentError, fn ->
      B58.decode58!("~")
    end

    # invalid leading character
    assert_raise ArgumentError, fn ->
      B58.decode58!("~Cn8eVZg")
    end

    # invalid trailing character
    assert_raise ArgumentError, fn ->
      B58.decode58!("Cn8eVZg^")
    end

    # invalid character mid string
    assert_raise ArgumentError, fn ->
      B58.decode58!("Cn8%eVZg")
    end

    # invalid character excluded from alphabet due to clarity
    assert_raise ArgumentError, fn ->
      B58.decode58!("OCn8eVZg")
    end

    # base16 encoded string
    assert_raise ArgumentError, fn ->
      "12209CBC07C3F991725836A3AA2A581CA2029198AA420B9D99BC0E131D9F3E2CBE47"
      |> B58.decode58!()
    end
  end

  test "decode58/1 Base58 handles invalid binaries when using the bitcoin alphabet" do
    # invalid character
    {:error, _} = B58.decode58("~")
    # invalid leading character
    {:error, _} = B58.decode58("~Cn8eVZg")
    # invalid trailing character
    {:error, _} = B58.decode58("Cn8eVZg^")
    # invalid character mid string
    {:error, _} = B58.decode58("Cn8%eVZg")
    # invalid character excluded from alphabet due to clarity
    {:error, _} = B58.decode58("OCn8eVZg")
    # base16 encoded string
    {:error, _} =
      "12209CBC07C3F991725836A3AA2A581CA2029198AA420B9D99BC0E131D9F3E2CBE47"
      |> B58.decode58()
  end

  test "decode58_check!/1 decodes Base58Check encoded binaries using the bitcoin alphabet" do
    assert B58.decode58_check!("12L5B5yqsf7vwb") == {"hello", <<0>>}
    assert B58.decode58_check!("B5oSH5yUDQS9XwzogrcWP") == {"hello world", <<1>>}
    assert B58.decode58_check!("YXMkDYBSTEWVuE2vQhQ1nc") == {"Hello World", <<255>>}
    assert B58.decode58_check!("1Wh4bh") == {<<>>, <<0>>}
  end

  test "decode58_check/1 decodes Base58Check encoded binaries using the bitcoin alphabet" do
    assert B58.decode58_check("12L5B5yqsf7vwb") == {:ok, {"hello", <<0>>}}
    assert B58.decode58_check("B5oSH5yUDQS9XwzogrcWP") == {:ok, {"hello world", <<1>>}}
    assert B58.decode58_check("YXMkDYBSTEWVuE2vQhQ1nc") == {:ok, {"Hello World", <<255>>}}
    assert B58.decode58_check("1Wh4bh") == {:ok, {<<>>, <<0>>}}
  end

  test "decode58_check!/1 Base58Check decodes to a RIPEMD-160 encoded hash" do
    # ex per: https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
    {hash_bin, version} =
      "1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs"
      |> B58.decode58_check!()

    assert version == <<0>>

    assert hash_bin
           |> Base.encode16(case: :lower) == "f54a5851e9372b87810a8e60cdd2e7cfd80b6e31"
  end

  test "decode58_check!/1 handles binaries with invalid checksums encoded using the bitcoin alphabet" do
    # corrupt last byte
    assert_raise ArgumentError, fn -> B58.decode58_check!("12L5B5yqsf7vwc") end
    # corrupt first byte
    assert_raise ArgumentError, fn -> B58.decode58_check!("D5oSH5yUDQS9XwzogrcWP") end
    # corrupt middle byte
    assert_raise ArgumentError, fn -> B58.decode58_check!("YXMkDYBSTEWWuE2vQhQ1nc") end
    # corrupted empty
    assert_raise ArgumentError, fn -> B58.decode58_check!("1Wi4bh") end
  end

  test "decode58_check/1 handles binaries with invalid checksums encoded using the bitcoin alphabet" do
    # corrupt last byte
    {:error, _} = B58.decode58_check("12L5B5yqsf7vwc")
    # corrupt first byte
    {:error, _} = B58.decode58_check("D5oSH5yUDQS9XwzogrcWP")
    # corrupt middle byte
    {:error, _} = B58.decode58_check("YXMkDYBSTEWWuE2vQhQ1nc")
    # corrupted empty
    {:error, _} = B58.decode58_check("1Wi4bh")
  end

  test "decode58_check!/1 handles invalid binaries when using encoding using the bitcoin alphabet" do
    # Zero is not in this alphabet
    assert_raise ArgumentError, fn -> B58.decode58_check!("012L5B5yqsf7vwb") end
    # Undescore is not in this alphabet
    assert_raise ArgumentError, fn -> B58.decode58_check!("B5oSH5yUDQS9XwzogrcW_") end
    # Base64 alphabet is not compatible
    assert_raise ArgumentError, fn ->
      "Hello World"
      |> Base.encode64()
      |> B58.decode58_check!()
    end

    # missing bytes
    assert_raise ArgumentError, fn -> B58.decode58_check!("1Wh4b") end
    assert_raise ArgumentError, fn -> B58.decode58_check!(<<>>) end
  end

  test "decode58_check/1 handles invalid binaries when using encoding using the bitcoin alphabet" do
    # Zero is not in this alphabet
    {:error, _} = B58.decode58_check("012L5B5yqsf7vwb")
    # Underscore is not in this alphabet
    {:error, _} = B58.decode58_check("B5oSH5yUDQS9XwzogrcW_")
    # Base64 alphabet is not compatible
    {:error, _} =
      "Hello World"
      |> Base.encode64()
      |> B58.decode58_check()

    # missing bytes
    {:error, _} = B58.decode58_check("1Wh4b")
    {:error, _} = B58.decode58_check(<<>>)
  end

  test "version_decode58_check!/1 decodes Base58Check encoded binaries using the bitcoin alphabet" do
    assert B58.version_decode58_check!("12L5B5yqsf7vwb") == <<0, "hello">>
    assert B58.version_decode58_check!("B5oSH5yUDQS9XwzogrcWP") == <<1, "hello world">>
    assert B58.version_decode58_check!("YXMkDYBSTEWVuE2vQhQ1nc") == <<255, "Hello World">>
    assert B58.version_decode58_check!("1Wh4bh") == <<0>>
  end

  test "version_decode58_check/1 decodes Base58Check encoded binaries using the bitcoin alphabet" do
    assert B58.version_decode58_check("12L5B5yqsf7vwb") == {:ok, <<0, "hello">>}
    assert B58.version_decode58_check("B5oSH5yUDQS9XwzogrcWP") == {:ok, <<1, "hello world">>}
    assert B58.version_decode58_check("YXMkDYBSTEWVuE2vQhQ1nc") == {:ok, <<255, "Hello World">>}
    assert B58.version_decode58_check("1Wh4bh") == {:ok, <<0>>}
  end

  test "version_decode58_check!/1 Base58Check decodes to a versioned RIPEMD-160 encoded hash" do
    # ex per: https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
    assert "1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs"
           |> B58.version_decode58_check!()
           |> :binary.decode_unsigned() == 0x0F54A5851E9372B87810A8E60CDD2E7CFD80B6E31
  end

  test "version_decode58_check!/1 handles binaries with invalid checksums encoded using the bitcoin alphabet" do
    # corrupt last byte
    assert_raise ArgumentError, fn -> B58.version_decode58_check!("12L5B5yqsf7vwc") end
    # corrupt first byte
    assert_raise ArgumentError, fn -> B58.version_decode58_check!("D5oSH5yUDQS9XwzogrcWP") end
    # corrupt middle byte
    assert_raise ArgumentError, fn -> B58.version_decode58_check!("YXMkDYBSTEWWuE2vQhQ1nc") end
    # corrupted empty
    assert_raise ArgumentError, fn -> B58.version_decode58_check!("1Wi4bh") end
  end

  test "version_decode58_check/1 handles binaries with invalid checksums encoded using the bitcoin alphabet" do
    # corrupt last byte
    {:error, _} = B58.version_decode58_check("12L5B5yqsf7vwc")
    # corrupt first byte
    {:error, _} = B58.version_decode58_check("D5oSH5yUDQS9XwzogrcWP")
    # corrupt middle byte
    {:error, _} = B58.version_decode58_check("YXMkDYBSTEWWuE2vQhQ1nc")
    # corrupted empty
    {:error, _} = B58.version_decode58_check("1Wi4bh")
  end

  test "version_decode58_check!/1 handles invalid binaries when using encoding using the bitcoin alphabet" do
    # Zero is not in this alphabet
    assert_raise ArgumentError, fn -> B58.version_decode58_check!("012L5B5yqsf7vwb") end
    # Undescore is not in this alphabet
    assert_raise ArgumentError, fn -> B58.version_decode58_check!("B5oSH5yUDQS9XwzogrcW_") end
    # Base64 alphabet is not compatible
    assert_raise ArgumentError, fn ->
      "Hello World"
      |> Base.encode64()
      |> B58.version_decode58_check!()
    end

    # missing bytes
    assert_raise ArgumentError, fn -> B58.version_decode58_check!("1Wh4b") end
    assert_raise ArgumentError, fn -> B58.version_decode58_check!(<<>>) end
  end

  test "version_decode58_check/1 handles invalid binaries when using encoding using the bitcoin alphabet" do
    # Zero is not in this alphabet
    {:error, _} = B58.version_decode58_check("012L5B5yqsf7vwb")
    # Underscore is not in this alphabet
    {:error, _} = B58.version_decode58_check("B5oSH5yUDQS9XwzogrcW_")
    # Base64 alphabet is not compatible
    {:error, _} =
      "Hello World"
      |> Base.encode64()
      |> B58.version_decode58_check()

    # missing bytes
    {:error, _} = B58.version_decode58_check("1Wh4b")
    {:error, _} = B58.version_decode58_check(<<>>)
  end

  # ============================================================================
  # Bitcoin
  # ============================================================================
  test "encode58/2 Base58 encodes strings according to the bitcoin alphabet" do
    assert B58.encode58("hello", alphabet: :btc) == "Cn8eVZg"
    assert B58.encode58("hello world", alphabet: :btc) == "StV1DL6CwTryKyV"
    assert B58.encode58("Hello World") == "JxF12TrwUP45BMd"
    assert B58.encode58(<<>>, alphabet: :btc) == <<>>
  end

  test "encode58/2 Base58 encodes sha-256 strings according to the bitcoin alphabet" do
    # From https://github.com/multiformats/multihash
    assert "12209CBC07C3F991725836A3AA2A581CA2029198AA420B9D99BC0E131D9F3E2CBE47"
           |> Base.decode16!()
           |> B58.encode58(alphabet: :btc) == "QmYtUc4iTCbbfVSDNKvtQqrfyezPPnFvE33wFmutw9PBBk"
  end

  test "encode58/2 handles encodes leading zeroes for the bitcoin alphabet" do
    assert B58.encode58(<<0>>, alphabet: :btc) == "1"
    assert B58.encode58(<<0, 0, 0, "hello world">>, alphabet: :btc) == "111StV1DL6CwTryKyV"
    assert B58.encode58(<<0, 0, 0>>, alphabet: :btc) == "111"
  end

  test "encode58_check!/3 accepts only unsigned single byte integers using the bitcoin alphabet" do
    assert B58.encode58_check!("a", <<0>>, alphabet: :btc) == "1C3t9Nib"
    assert B58.encode58_check!("a", 0, alphabet: :btc) == "1C3t9Nib"
    assert B58.encode58_check!("a", <<1>>, alphabet: :btc) == "gqkwoXD"
    assert B58.encode58_check!("a", 1, alphabet: :btc) == "gqkwoXD"
    assert B58.encode58_check!("a", <<2>>, alphabet: :btc) == "2BkJbhjW"
    assert B58.encode58_check!("a", 2, alphabet: :btc) == "2BkJbhjW"
    assert B58.encode58_check!("a", <<255>>, alphabet: :btc) == "3CAw3RMCe"
    assert B58.encode58_check!("a", 255, alphabet: :btc) == "3CAw3RMCe"
    assert B58.encode58_check!(<<>>, <<2>>, alphabet: :btc) == "Epi3KP"
    assert B58.encode58_check!(<<>>, 2, alphabet: :btc) == "Epi3KP"

    assert_raise ArgumentError, fn ->
      B58.encode58_check!("a", 256, alphabet: :btc)
    end

    assert_raise ArgumentError, fn ->
      B58.encode58_check!("a", -1, alphabet: :btc)
    end

    assert_raise ArgumentError, fn ->
      B58.encode58_check!("a", <<1, 0>>, alphabet: :btc)
    end
  end

  test "encode58_check!/3 Base58Check encodes strings according to the bitcoin alphabet" do
    assert B58.encode58_check!("hello", 0, alphabet: :btc) == "12L5B5yqsf7vwb"
    assert B58.encode58_check!("hello world", 1, alphabet: :btc) == "B5oSH5yUDQS9XwzogrcWP"
    assert B58.encode58_check!("Hello World", 255, alphabet: :btc) == "YXMkDYBSTEWVuE2vQhQ1nc"
    assert B58.encode58_check!(<<>>, 0, alphabet: :btc) == "1Wh4bh"
  end

  test "encode58_check/3 Base58Check encodes strings according to the bitcoin alphabet" do
    assert B58.encode58_check("hello", 0, alphabet: :btc) == {:ok, "12L5B5yqsf7vwb"}
    assert B58.encode58_check("hello world", 1, alphabet: :btc) == {:ok, "B5oSH5yUDQS9XwzogrcWP"}

    assert B58.encode58_check("Hello World", 255, alphabet: :btc) ==
             {:ok, "YXMkDYBSTEWVuE2vQhQ1nc"}

    assert B58.encode58_check(<<>>, 0, alphabet: :btc) == {:ok, "1Wh4bh"}
  end

  test "encode58_check!/3 Base58Check encodes sha-256 strings according to the bitcoin alphabet" do
    # From https://github.com/multiformats/multihash
    assert "12209CBC07C3F991725836A3AA2A581CA2029198AA420B9D99BC0E131D9F3E2CBE47"
           |> Base.decode16!()
           |> B58.encode58_check!(0, alphabet: :btc) ==
             "13gXk986h9pApW3uNeGAHDqUnYHo8c1oSfHajVDuzPtiSokwhzzeK"
  end

  test "encode58_check!/3 Base58Check encodes a RIPEMD-160 hash" do
    # ex per: https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
    assert "f54a5851e9372b87810a8e60cdd2e7cfd80b6e31"
           |> Base.decode16!(case: :lower)
           |> B58.encode58_check!(0, alphabet: :btc) == "1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs"
  end

  test "encode58_check!/2 handles Base58 encoding leading zeroes" do
    assert B58.encode58_check!(<<0>>, 0, alphabet: :btc) == "112edB6q"

    assert B58.encode58_check!(<<0, 0, 0, "hello world">>, 0, alphabet: :btc) ==
             "11113vQB7B6MrGQZaxCrokgx4"

    assert B58.encode58_check!(<<0, 0, 0>>, 0, alphabet: :btc) == "11114bdQda"
  end

  test "version_encode58_check!/3 accepts unsigned single byte integer versions" do
    assert B58.version_encode58_check!(<<0, "a">>, alphabet: :btc) == "1C3t9Nib"
    assert B58.version_encode58_check!(<<1, "a">>, alphabet: :btc) == "gqkwoXD"
    assert B58.version_encode58_check!(<<2, "a">>, alphabet: :btc) == "2BkJbhjW"
    assert B58.version_encode58_check!(<<255, "a">>, alphabet: :btc) == "3CAw3RMCe"
    assert B58.version_encode58_check!(<<2>>, alphabet: :btc) == "Epi3KP"
  end

  test "version_encode58_check/3 Base58Check encodes strings according to the bitcoin alphabet" do
    assert B58.version_encode58_check(<<0, "hello">>, alphabet: :btc) == {:ok, "12L5B5yqsf7vwb"}

    assert B58.version_encode58_check(<<1, "hello world">>, alphabet: :btc) ==
             {:ok, "B5oSH5yUDQS9XwzogrcWP"}

    assert B58.version_encode58_check(<<255, "Hello World">>, alphabet: :btc) ==
             {:ok, "YXMkDYBSTEWVuE2vQhQ1nc"}

    assert B58.version_encode58_check(<<0>>, alphabet: :btc) == {:ok, "1Wh4bh"}
  end

  test "version_encode58_check!/3 Base58Check encodes strings according to the bitcoin alphabet" do
    assert B58.version_encode58_check!(<<0, "hello">>, alphabet: :btc) == "12L5B5yqsf7vwb"

    assert B58.version_encode58_check!(<<1, "hello world">>, alphabet: :btc) ==
             "B5oSH5yUDQS9XwzogrcWP"

    assert B58.version_encode58_check!(<<255, "Hello World">>, alphabet: :btc) ==
             "YXMkDYBSTEWVuE2vQhQ1nc"

    assert B58.version_encode58_check!(<<0>>, alphabet: :btc) == "1Wh4bh"
  end

  test "version_encode58_check!/2 Base58Check encodes a versioned RIPEMD-160 hash" do
    # ex per: https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
    assert 0xF54A5851E9372B87810A8E60CDD2E7CFD80B6E31
           |> :binary.encode_unsigned()
           |> B58.version_binary(0)
           |> B58.version_encode58_check!(alphabet: :btc) == "1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs"
  end

  test "version_encode58_check!/2 handles Base58 encoding leading zeroes" do
    assert B58.version_encode58_check!(<<0, 0>>, alphabet: :btc) == "112edB6q"

    assert B58.version_encode58_check!(<<0, 0, 0, 0, "hello world">>, alphabet: :btc) ==
             "11113vQB7B6MrGQZaxCrokgx4"

    assert B58.version_encode58_check!(<<0, 0, 0, 0>>, alphabet: :btc) == "11114bdQda"
  end

  test "decode58!/2 decodes Base58 encoded binaries using the bitcoin alphabet" do
    assert B58.decode58!("Cn8eVZg", alphabet: :btc) == "hello"
    assert B58.decode58!("StV1DL6CwTryKyV", alphabet: :btc) == "hello world"
    assert B58.decode58!("JxF12TrwUP45BMd", alphabet: :btc) == "Hello World"
    assert B58.decode58!(<<>>, alphabet: :btc) == <<>>
  end

  test "decode58!/2 handles Base58 encoded with leading zeroes using the bitcoin alphabet" do
    assert B58.decode58!("1", alphabet: :btc) == <<0>>
    assert B58.decode58!("111StV1DL6CwTryKyV", alphabet: :btc) == <<0, 0, 0, "hello world">>
    assert B58.decode58!("111", alphabet: :btc) == <<0, 0, 0>>
  end

  test "decode58!/2 Base58 decodes sha-256 strings using the bitcoin alphabet" do
    # From https://github.com/multiformats/multihash
    assert "QmYtUc4iTCbbfVSDNKvtQqrfyezPPnFvE33wFmutw9PBBk"
           |> B58.decode58!(alphabet: :btc)
           |> Base.encode16() ==
             "12209CBC07C3F991725836A3AA2A581CA2029198AA420B9D99BC0E131D9F3E2CBE47"
  end

  test "decode58!/2 Base58 handles invalid binaries when using the bitcoin alphabet" do
    # invalid character
    assert_raise ArgumentError, fn ->
      B58.decode58!("~", alphabet: :btc)
    end

    # invalid leading character
    assert_raise ArgumentError, fn ->
      B58.decode58!("~Cn8eVZg", alphabet: :btc)
    end

    # invalid trailing character
    assert_raise ArgumentError, fn ->
      B58.decode58!("Cn8eVZg^", alphabet: :btc)
    end

    # invalid character mid string
    assert_raise ArgumentError, fn ->
      B58.decode58!("Cn8%eVZg", alphabet: :btc)
    end

    # invalid character excluded from alphabet due to clarity
    assert_raise ArgumentError, fn ->
      B58.decode58!("OCn8eVZg", alphabet: :btc)
    end

    # base16 encoded string
    assert_raise ArgumentError, fn ->
      "12209CBC07C3F991725836A3AA2A581CA2029198AA420B9D99BC0E131D9F3E2CBE47"
      |> B58.decode58!(alphabet: :btc)
    end
  end

  test "decode58/2 Base58 handles invalid binaries when using the bitcoin alphabet" do
    # invalid character
    {:error, _} = B58.decode58("~", alphabet: :btc)
    # invalid leading character
    {:error, _} = B58.decode58("~Cn8eVZg", alphabet: :btc)
    # invalid trailing character
    {:error, _} = B58.decode58("Cn8eVZg^", alphabet: :btc)
    # invalid character mid string
    {:error, _} = B58.decode58("Cn8%eVZg", alphabet: :btc)
    # invalid character excluded from alphabet due to clarity
    {:error, _} = B58.decode58("OCn8eVZg", alphabet: :btc)
    # base16 encoded string
    {:error, _} =
      "12209CBC07C3F991725836A3AA2A581CA2029198AA420B9D99BC0E131D9F3E2CBE47"
      |> B58.decode58(alphabet: :btc)
  end

  test "decode58_check!/2 decodes Base58Check encoded binaries using the bitcoin alphabet" do
    assert B58.decode58_check!("12L5B5yqsf7vwb", alphabet: :btc) == {"hello", <<0>>}
    assert B58.decode58_check!("B5oSH5yUDQS9XwzogrcWP", alphabet: :btc) == {"hello world", <<1>>}

    assert B58.decode58_check!("YXMkDYBSTEWVuE2vQhQ1nc", alphabet: :btc) ==
             {"Hello World", <<255>>}

    assert B58.decode58_check!("1Wh4bh", alphabet: :btc) == {<<>>, <<0>>}
  end

  test "decode58_check/2 decodes Base58Check encoded binaries using the bitcoin alphabet" do
    assert B58.decode58_check("12L5B5yqsf7vwb", alphabet: :btc) == {:ok, {"hello", <<0>>}}

    assert B58.decode58_check("B5oSH5yUDQS9XwzogrcWP", alphabet: :btc) ==
             {:ok, {"hello world", <<1>>}}

    assert B58.decode58_check("YXMkDYBSTEWVuE2vQhQ1nc", alphabet: :btc) ==
             {:ok, {"Hello World", <<255>>}}

    assert B58.decode58_check("1Wh4bh", alphabet: :btc) == {:ok, {<<>>, <<0>>}}
  end

  test "decode58_check!/2 Base58Check decodes to a RIPEMD-160 encoded hash" do
    # ex per: https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
    {hash_bin, version} =
      "1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs"
      |> B58.decode58_check!(alphabet: :btc)

    assert version == <<0>>

    assert hash_bin
           |> Base.encode16(case: :lower) == "f54a5851e9372b87810a8e60cdd2e7cfd80b6e31"
  end

  test "decode58_check!/2 handles binaries with invalid checksums encoded using the bitcoin alphabet" do
    # corrupt last byte
    assert_raise ArgumentError, fn -> B58.decode58_check!("12L5B5yqsf7vwc", alphabet: :btc) end
    # corrupt first byte
    assert_raise ArgumentError, fn ->
      B58.decode58_check!("D5oSH5yUDQS9XwzogrcWP", alphabet: :btc)
    end

    # corrupt middle byte
    assert_raise ArgumentError, fn ->
      B58.decode58_check!("YXMkDYBSTEWWuE2vQhQ1nc", alphabet: :btc)
    end

    # corrupted empty
    assert_raise ArgumentError, fn -> B58.decode58_check!("1Wi4bh", alphabet: :btc) end
  end

  test "decode58_check/2 handles binaries with invalid checksums encoded using the bitcoin alphabet" do
    # corrupt last byte
    {:error, _} = B58.decode58_check("12L5B5yqsf7vwc", alphabet: :btc)
    # corrupt first byte
    {:error, _} = B58.decode58_check("D5oSH5yUDQS9XwzogrcWP", alphabet: :btc)
    # corrupt middle byte
    {:error, _} = B58.decode58_check("YXMkDYBSTEWWuE2vQhQ1nc", alphabet: :btc)
    # corrupted empty
    {:error, _} = B58.decode58_check("1Wi4bh", alphabet: :btc)
  end

  test "decode58_check!/2 handles invalid binaries when using encoding using the bitcoin alphabet" do
    # Zero is not in this alphabet
    assert_raise ArgumentError, fn -> B58.decode58_check!("012L5B5yqsf7vwb", alphabet: :btc) end
    # Underscore is not in this alphabet
    assert_raise ArgumentError, fn ->
      B58.decode58_check!("B5oSH5yUDQS9XwzogrcW_", alphabet: :btc)
    end

    # Base64 alphabet is not compatible
    assert_raise ArgumentError, fn ->
      "Hello World"
      |> Base.encode64()
      |> B58.decode58_check!(alphabet: :btc)
    end

    # missing bytes
    assert_raise ArgumentError, fn -> B58.decode58_check!("1Wh4b", alphabet: :btc) end
    assert_raise ArgumentError, fn -> B58.decode58_check!(<<>>, alphabet: :btc) end
  end

  test "decode58_check/2 handles invalid binaries when using encoding using the bitcoin alphabet" do
    # Zero is not in this alphabet
    {:error, _} = B58.decode58_check("012L5B5yqsf7vwb", alphabet: :btc)
    # Underscore is not in this alphabet
    {:error, _} = B58.decode58_check("B5oSH5yUDQS9XwzogrcW_", alphabet: :btc)
    # Base64 alphabet is not compatible
    {:error, _} =
      "Hello World"
      |> Base.encode64()
      |> B58.decode58_check(alphabet: :btc)

    # missing bytes
    {:error, _} = B58.decode58_check("1Wh4b", alphabet: :btc)
    {:error, _} = B58.decode58_check(<<>>, alphabet: :btc)
  end

  test "version_decode58_check!/2 decodes Base58Check encoded binaries using the bitcoin alphabet" do
    assert B58.version_decode58_check!("12L5B5yqsf7vwb", alphabet: :btc) == <<0, "hello">>

    assert B58.version_decode58_check!("B5oSH5yUDQS9XwzogrcWP", alphabet: :btc) ==
             <<1, "hello world">>

    assert B58.version_decode58_check!("YXMkDYBSTEWVuE2vQhQ1nc", alphabet: :btc) ==
             <<255, "Hello World">>

    assert B58.version_decode58_check!("1Wh4bh", alphabet: :btc) == <<0>>
  end

  test "version_decode58_check/2 decodes Base58Check encoded binaries using the bitcoin alphabet" do
    assert B58.version_decode58_check("12L5B5yqsf7vwb", alphabet: :btc) == {:ok, <<0, "hello">>}

    assert B58.version_decode58_check("B5oSH5yUDQS9XwzogrcWP", alphabet: :btc) ==
             {:ok, <<1, "hello world">>}

    assert B58.version_decode58_check("YXMkDYBSTEWVuE2vQhQ1nc", alphabet: :btc) ==
             {:ok, <<255, "Hello World">>}

    assert B58.version_decode58_check("1Wh4bh", alphabet: :btc) == {:ok, <<0>>}
  end

  test "version_decode58_check!/2 Base58Check decodes to a versioned RIPEMD-160 encoded hash" do
    # ex per: https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
    assert "1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs"
           |> B58.version_decode58_check!(alphabet: :btc)
           |> :binary.decode_unsigned() == 0x0F54A5851E9372B87810A8E60CDD2E7CFD80B6E31
  end

  test "version_decode58_check!/2 handles binaries with invalid checksums encoded using the bitcoin alphabet" do
    # corrupt last byte
    assert_raise ArgumentError, fn ->
      B58.version_decode58_check!("12L5B5yqsf7vwc", alphabet: :btc)
    end

    # corrupt first byte
    assert_raise ArgumentError, fn ->
      B58.version_decode58_check!("D5oSH5yUDQS9XwzogrcWP", alphabet: :btc)
    end

    # corrupt middle byte
    assert_raise ArgumentError, fn ->
      B58.version_decode58_check!("YXMkDYBSTEWWuE2vQhQ1nc", alphabet: :btc)
    end

    # corrupted empty
    assert_raise ArgumentError, fn -> B58.version_decode58_check!("1Wi4bh", alphabet: :btc) end
  end

  test "version_decode58_check/2 handles binaries with invalid checksums encoded using the bitcoin alphabet" do
    # corrupt last byte
    {:error, _} = B58.version_decode58_check("12L5B5yqsf7vwc", alphabet: :btc)
    # corrupt first byte
    {:error, _} = B58.version_decode58_check("D5oSH5yUDQS9XwzogrcWP", alphabet: :btc)
    # corrupt middle byte
    {:error, _} = B58.version_decode58_check("YXMkDYBSTEWWuE2vQhQ1nc", alphabet: :btc)
    # corrupted empty
    {:error, _} = B58.version_decode58_check("1Wi4bh", alphabet: :btc)
  end

  test "version_decode58_check!/2 handles invalid binaries when using encoding using the bitcoin alphabet" do
    # Zero is not in this alphabet
    assert_raise ArgumentError, fn ->
      B58.version_decode58_check!("012L5B5yqsf7vwb", alphabet: :btc)
    end

    # Underscore is not in this alphabet
    assert_raise ArgumentError, fn ->
      B58.version_decode58_check!("B5oSH5yUDQS9XwzogrcW_", alphabet: :btc)
    end

    # Base64 alphabet is not compatible
    assert_raise ArgumentError, fn ->
      "Hello World"
      |> Base.encode64()
      |> B58.version_decode58_check!(alphabet: :btc)
    end

    # missing bytes
    assert_raise ArgumentError, fn -> B58.version_decode58_check!("1Wh4b", alphabet: :btc) end
    assert_raise ArgumentError, fn -> B58.version_decode58_check!(<<>>, alphabet: :btc) end
  end

  test "version_decode58_check/2 handles invalid binaries when using encoding using the bitcoin alphabet" do
    # Zero is not in this alphabet
    {:error, _} = B58.version_decode58_check("012L5B5yqsf7vwb", alphabet: :btc)
    # Underscore is not in this alphabet
    {:error, _} = B58.version_decode58_check("B5oSH5yUDQS9XwzogrcW_", alphabet: :btc)
    # Base64 alphabet is not compatible
    {:error, _} =
      "Hello World"
      |> Base.encode64()
      |> B58.version_decode58_check(alphabet: :btc)

    # missing bytes
    {:error, _} = B58.version_decode58_check("1Wh4b", alphabet: :btc)
    {:error, _} = B58.version_decode58_check(<<>>, alphabet: :btc)
  end

  # ============================================================================
  # Flickr
  # ============================================================================
  test "encode58/2 Base58 encodes strings according to the flickr alphabet" do
    assert B58.encode58("hello", alphabet: :flickr) == "cM8DuyF"
    assert B58.encode58("hello world", alphabet: :flickr) == "rTu1dk6cWsRYjYu"
    assert B58.encode58("Hello World", alphabet: :flickr) == "iXf12sRWto45bmC"
    assert B58.encode58(<<>>, alphabet: :flickr) == <<>>
  end

  test "encode58/2 Base58 encodes sha-256 strings according to the flickr alphabet" do
    # From https://github.com/multiformats/multihash
    assert "12209CBC07C3F991725836A3AA2A581CA2029198AA420B9D99BC0E131D9F3E2CBE47"
           |> Base.decode16!()
           |> B58.encode58(alphabet: :flickr) == "pLxTtB4HscAAEurdnjVTpQREYDZooMfVe33WfLUTW9obbK"
  end

  test "encode58/2 handles encodes leading zeroes for the flickr alphabet" do
    assert B58.encode58(<<0>>, alphabet: :flickr) == "1"
    assert B58.encode58(<<0, 0, 0, "hello world">>, alphabet: :flickr) == "111rTu1dk6cWsRYjYu"
    assert B58.encode58(<<0, 0, 0>>, alphabet: :flickr) == "111"
  end

  test "encode58_check!/3 accepts only unsigned single byte integers using the flickr alphabet" do
    assert B58.encode58_check!("a", <<0>>, alphabet: :flickr) == "1c3T9nHA"
    assert B58.encode58_check!("a", 0, alphabet: :flickr) == "1c3T9nHA"
    assert B58.encode58_check!("a", <<1>>, alphabet: :flickr) == "FQKWNwd"
    assert B58.encode58_check!("a", 1, alphabet: :flickr) == "FQKWNwd"
    assert B58.encode58_check!("a", <<2>>, alphabet: :flickr) == "2bKiAGJv"
    assert B58.encode58_check!("a", 2, alphabet: :flickr) == "2bKiAGJv"
    assert B58.encode58_check!("a", <<255>>, alphabet: :flickr) == "3caW3qmcD"
    assert B58.encode58_check!("a", 255, alphabet: :flickr) == "3caW3qmcD"
    assert B58.encode58_check!(<<>>, <<2>>, alphabet: :flickr) == "ePH3jo"
    assert B58.encode58_check!(<<>>, 2, alphabet: :flickr) == "ePH3jo"

    assert_raise ArgumentError, fn ->
      B58.encode58_check!("a", 256, alphabet: :flickr)
    end

    assert_raise ArgumentError, fn ->
      B58.encode58_check!("a", -1, alphabet: :flickr)
    end

    assert_raise ArgumentError, fn ->
      B58.encode58_check!("a", <<1, 0>>, alphabet: :flickr)
    end
  end

  test "encode58_check!/3 Base58Check encodes strings according to the flickr alphabet" do
    assert B58.encode58_check!("hello", 0, alphabet: :flickr) == "12k5b5YQSE7VWA"
    assert B58.encode58_check!("hello world", 1, alphabet: :flickr) == "b5Nrh5Ytdpr9wWZNFRBvo"
    assert B58.encode58_check!("Hello World", 255, alphabet: :flickr) == "xwmKdxbrsevuUe2VpGp1MB"
    assert B58.encode58_check!(<<>>, 0, alphabet: :flickr) == "1vG4AG"
  end

  test "encode58_check/3 Base58Check encodes strings according to the flickr alphabet" do
    assert B58.encode58_check("hello", 0, alphabet: :flickr) == {:ok, "12k5b5YQSE7VWA"}

    assert B58.encode58_check("hello world", 1, alphabet: :flickr) ==
             {:ok, "b5Nrh5Ytdpr9wWZNFRBvo"}

    assert B58.encode58_check("Hello World", 255, alphabet: :flickr) ==
             {:ok, "xwmKdxbrsevuUe2VpGp1MB"}

    assert B58.encode58_check(<<>>, 0, alphabet: :flickr) == {:ok, "1vG4AG"}
  end

  test "encode58_check!/3 Base58Check encodes sha-256 strings according to the flickr alphabet" do
    # From https://github.com/multiformats/multihash
    assert "12209CBC07C3F991725836A3AA2A581CA2029198AA420B9D99BC0E131D9F3E2CBE47"
           |> Base.decode16!()
           |> B58.encode58_check!(0, alphabet: :flickr) ==
             "13FwK986G9PaPv3UnDgahdQtMxhN8B1NrEhzJudUZoTHrNKWGZZDj"
  end

  test "encode58_check!/3 Base58Check encodes a RIPEMD-160 hash using the flickr alphabet" do
    # ex per: https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
    assert "f54a5851e9372b87810a8e60cdd2e7cfd80b6e31"
           |> Base.decode16!(case: :lower)
           |> B58.encode58_check!(0, alphabet: :flickr) == "1omYBzBMizrQWWiQJzWwbeRMkSy7qKwtaS"
  end

  test "encode58_check!/2 handles Base58 encoding leading zeroes using the flickr alphabet" do
    assert B58.encode58_check!(<<0>>, 0, alphabet: :flickr) == "112DCb6Q"

    assert B58.encode58_check!(<<0, 0, 0, "hello world">>, 0, alphabet: :flickr) ==
             "11113Vpb7b6mRgpyzXcRNKFX4"

    assert B58.encode58_check!(<<0, 0, 0>>, 0, alphabet: :flickr) == "11114ACpCz"
  end

  test "version_encode58_check!/3 accepts unsigned single byte integer versions using the flickr alphabet" do
    assert B58.version_encode58_check!(<<0, "a">>, alphabet: :flickr) == "1c3T9nHA"
    assert B58.version_encode58_check!(<<1, "a">>, alphabet: :flickr) == "FQKWNwd"
    assert B58.version_encode58_check!(<<2, "a">>, alphabet: :flickr) == "2bKiAGJv"
    assert B58.version_encode58_check!(<<255, "a">>, alphabet: :flickr) == "3caW3qmcD"
    assert B58.version_encode58_check!(<<2>>, alphabet: :flickr) == "ePH3jo"
  end

  test "version_encode58_check/3 Base58Check encodes strings according to the flickr alphabet" do
    assert B58.version_encode58_check(<<0, "hello">>, alphabet: :flickr) ==
             {:ok, "12k5b5YQSE7VWA"}

    assert B58.version_encode58_check(<<1, "hello world">>, alphabet: :flickr) ==
             {:ok, "b5Nrh5Ytdpr9wWZNFRBvo"}

    assert B58.version_encode58_check(<<255, "Hello World">>, alphabet: :flickr) ==
             {:ok, "xwmKdxbrsevuUe2VpGp1MB"}

    assert B58.version_encode58_check(<<0>>, alphabet: :flickr) == {:ok, "1vG4AG"}
  end

  test "version_encode58_check!/3 Base58Check encodes strings according to the flickr alphabet" do
    assert B58.version_encode58_check!(<<0, "hello">>, alphabet: :flickr) == "12k5b5YQSE7VWA"

    assert B58.version_encode58_check!(<<1, "hello world">>, alphabet: :flickr) ==
             "b5Nrh5Ytdpr9wWZNFRBvo"

    assert B58.version_encode58_check!(<<255, "Hello World">>, alphabet: :flickr) ==
             "xwmKdxbrsevuUe2VpGp1MB"

    assert B58.version_encode58_check!(<<0>>, alphabet: :flickr) == "1vG4AG"
  end

  test "version_encode58_check!/2 Base58Check encodes a versioned RIPEMD-160 hash using the flickr alphabet" do
    # ex per: https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
    assert 0xF54A5851E9372B87810A8E60CDD2E7CFD80B6E31
           |> :binary.encode_unsigned()
           |> B58.version_binary(0)
           |> B58.version_encode58_check!(alphabet: :flickr) ==
             "1omYBzBMizrQWWiQJzWwbeRMkSy7qKwtaS"
  end

  test "version_encode58_check!/2 handles Base58 encoding leading zeroes using the flickr alphabet" do
    assert B58.version_encode58_check!(<<0, 0>>, alphabet: :flickr) == "112DCb6Q"

    assert B58.version_encode58_check!(<<0, 0, 0, 0, "hello world">>, alphabet: :flickr) ==
             "11113Vpb7b6mRgpyzXcRNKFX4"

    assert B58.version_encode58_check!(<<0, 0, 0, 0>>, alphabet: :flickr) == "11114ACpCz"
  end

  test "decode58!/2 decodes Base58 encoded binaries using the flickr alphabet" do
    assert B58.decode58!("cM8DuyF", alphabet: :flickr) == "hello"
    assert B58.decode58!("rTu1dk6cWsRYjYu", alphabet: :flickr) == "hello world"
    assert B58.decode58!("iXf12sRWto45bmC", alphabet: :flickr) == "Hello World"
    assert B58.decode58!(<<>>, alphabet: :flickr) == <<>>
  end

  test "decode58!/2 handles Base58 encoded with leading zeroes using the flickr alphabet" do
    assert B58.decode58!("1", alphabet: :flickr) == <<0>>
    assert B58.decode58!("111rTu1dk6cWsRYjYu", alphabet: :flickr) == <<0, 0, 0, "hello world">>
    assert B58.decode58!("111", alphabet: :flickr) == <<0, 0, 0>>
  end

  test "decode58!/2 Base58 decodes sha-256 strings using the flickr alphabet" do
    # From https://github.com/multiformats/multihash
    assert "pLxTtB4HscAAEurdnjVTpQREYDZooMfVe33WfLUTW9obbK"
           |> B58.decode58!(alphabet: :flickr)
           |> Base.encode16() ==
             "12209CBC07C3F991725836A3AA2A581CA2029198AA420B9D99BC0E131D9F3E2CBE47"
  end

  test "decode58!/2 Base58 handles invalid binaries when using the flickr alphabet" do
    # invalid character
    assert_raise ArgumentError, fn ->
      B58.decode58!("~", alphabet: :flickr)
    end

    # invalid leading character
    assert_raise ArgumentError, fn ->
      B58.decode58!("~Cn8eVZg", alphabet: :flickr)
    end

    # invalid trailing character
    assert_raise ArgumentError, fn ->
      B58.decode58!("Cn8eVZg^", alphabet: :flickr)
    end

    # invalid character mid string
    assert_raise ArgumentError, fn ->
      B58.decode58!("Cn8%eVZg", alphabet: :flickr)
    end

    # invalid character excluded from alphabet due to clarity
    assert_raise ArgumentError, fn ->
      B58.decode58!("OCn8eVZg", alphabet: :flickr)
    end

    # base16 encoded string
    assert_raise ArgumentError, fn ->
      "12209CBC07C3F991725836A3AA2A581CA2029198AA420B9D99BC0E131D9F3E2CBE47"
      |> B58.decode58!(alphabet: :flickr)
    end
  end

  test "decode58/2 Base58 handles invalid binaries when using the flickr alphabet" do
    # invalid character
    {:error, _} = B58.decode58("~", alphabet: :flickr)
    # invalid leading character
    {:error, _} = B58.decode58("~cM8DuyF", alphabet: :flickr)
    # invalid trailing character
    {:error, _} = B58.decode58("cM8DuyF^", alphabet: :flickr)
    # invalid character mid string
    {:error, _} = B58.decode58("cM%DuyF", alphabet: :flickr)
    # invalid character excluded from alphabet due to clarity
    {:error, _} = B58.decode58("OcM8DuyF", alphabet: :flickr)
    # base16 encoded string
    {:error, _} =
      "12209CBC07C3F991725836A3AA2A581CA2029198AA420B9D99BC0E131D9F3E2CBE47"
      |> B58.decode58(alphabet: :flickr)
  end

  test "decode58_check!/2 decodes Base58Check encoded binaries using the flickr alphabet" do
    assert B58.decode58_check!("12k5b5YQSE7VWA", alphabet: :flickr) == {"hello", <<0>>}

    assert B58.decode58_check!("b5Nrh5Ytdpr9wWZNFRBvo", alphabet: :flickr) ==
             {"hello world", <<1>>}

    assert B58.decode58_check!("xwmKdxbrsevuUe2VpGp1MB", alphabet: :flickr) ==
             {"Hello World", <<255>>}

    assert B58.decode58_check!("1vG4AG", alphabet: :flickr) == {<<>>, <<0>>}
  end

  test "decode58_check/2 decodes Base58Check encoded binaries using the flickr alphabet" do
    assert B58.decode58_check("12k5b5YQSE7VWA", alphabet: :flickr) == {:ok, {"hello", <<0>>}}

    assert B58.decode58_check("b5Nrh5Ytdpr9wWZNFRBvo", alphabet: :flickr) ==
             {:ok, {"hello world", <<1>>}}

    assert B58.decode58_check("xwmKdxbrsevuUe2VpGp1MB", alphabet: :flickr) ==
             {:ok, {"Hello World", <<255>>}}

    assert B58.decode58_check("1vG4AG", alphabet: :flickr) == {:ok, {<<>>, <<0>>}}
  end

  test "decode58_check!/2 Base58Check decodes to a RIPEMD-160 encoded hash using the flickr alphabet" do
    # ex per: https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
    {hash_bin, version} =
      "1omYBzBMizrQWWiQJzWwbeRMkSy7qKwtaS"
      |> B58.decode58_check!(alphabet: :flickr)

    assert version == <<0>>

    assert hash_bin
           |> Base.encode16(case: :lower) == "f54a5851e9372b87810a8e60cdd2e7cfd80b6e31"
  end

  test "decode58_check!/2 handles binaries with invalid checksums encoded using the flickr alphabet" do
    # corrupt last byte
    assert_raise ArgumentError, fn -> B58.decode58_check!("12k5b5YQSE7VWB", alphabet: :flickr) end
    # corrupt first byte
    assert_raise ArgumentError, fn ->
      B58.decode58_check!("x5Nrh5Ytdpr9wWZNFRBvo", alphabet: :flickr)
    end

    # corrupt middle byte
    assert_raise ArgumentError, fn ->
      B58.decode58_check!("xwmKdxbrssvuUe2VpGp1MB", alphabet: :flickr)
    end

    # corrupted empty
    assert_raise ArgumentError, fn -> B58.decode58_check!("1vG4AB", alphabet: :flickr) end
  end

  test "decode58_check/2 handles binaries with invalid checksums encoded using the flickr alphabet" do
    # corrupt last byte
    {:error, _} = B58.decode58_check("12k5b5YQSE7VWB", alphabet: :flickr)
    # corrupt first byte
    {:error, _} = B58.decode58_check("x5Nrh5Ytdpr9wWZNFRBvo", alphabet: :flickr)
    # corrupt middle byte
    {:error, _} = B58.decode58_check("xwmKdxbrssvuUe2VpGp1MB", alphabet: :flickr)
    # corrupted empty
    {:error, _} = B58.decode58_check("1vG4AB", alphabet: :flickr)
  end

  test "decode58_check!/2 handles invalid binaries when using encoding using the flickr alphabet" do
    # Zero is not in this alphabet
    assert_raise ArgumentError, fn -> B58.decode58_check!("02k5b5YQSE7VWA", alphabet: :flickr) end
    # Underscore is not in this alphabet
    assert_raise ArgumentError, fn ->
      B58.decode58_check!("b5Nrh5Ytdpr9wWZNFRBvo_", alphabet: :flickr)
    end

    # Base64 alphabet is not compatible
    assert_raise ArgumentError, fn ->
      "Hello World"
      |> Base.encode64()
      |> B58.decode58_check!(alphabet: :flickr)
    end

    # missing bytes
    assert_raise ArgumentError, fn -> B58.decode58_check!("1v4AG", alphabet: :flickr) end
    assert_raise ArgumentError, fn -> B58.decode58_check!(<<>>, alphabet: :flickr) end
  end

  test "decode58_check/2 handles invalid binaries when using encoding using the flickr alphabet" do
    # Zero is not in this alphabet
    {:error, _} = B58.decode58_check("02k5b5YQSE7VWA", alphabet: :flickr)
    # Underscore is not in this alphabet
    {:error, _} = B58.decode58_check("b5Nrh5Ytdpr9wWZNFRBvo_", alphabet: :flickr)
    # Base64 alphabet is not compatible
    {:error, _} =
      "Hello World"
      |> Base.encode64()
      |> B58.decode58_check(alphabet: :flickr)

    # missing bytes
    {:error, _} = B58.decode58_check("1v4AG", alphabet: :flickr)
    {:error, _} = B58.decode58_check(<<>>, alphabet: :flickr)
  end

  test "version_decode58_check!/2 decodes Base58Check encoded binaries using the flickr alphabet" do
    assert B58.version_decode58_check!("12k5b5YQSE7VWA", alphabet: :flickr) == <<0, "hello">>

    assert B58.version_decode58_check!("b5Nrh5Ytdpr9wWZNFRBvo", alphabet: :flickr) ==
             <<1, "hello world">>

    assert B58.version_decode58_check!("xwmKdxbrsevuUe2VpGp1MB", alphabet: :flickr) ==
             <<255, "Hello World">>

    assert B58.version_decode58_check!("1vG4AG", alphabet: :flickr) == <<0>>
  end

  test "version_decode58_check/2 decodes Base58Check encoded binaries using the flickr alphabet" do
    assert B58.version_decode58_check("12k5b5YQSE7VWA", alphabet: :flickr) ==
             {:ok, <<0, "hello">>}

    assert B58.version_decode58_check("b5Nrh5Ytdpr9wWZNFRBvo", alphabet: :flickr) ==
             {:ok, <<1, "hello world">>}

    assert B58.version_decode58_check("xwmKdxbrsevuUe2VpGp1MB", alphabet: :flickr) ==
             {:ok, <<255, "Hello World">>}

    assert B58.version_decode58_check("1vG4AG", alphabet: :flickr) == {:ok, <<0>>}
  end

  test "version_decode58_check!/2 Base58Check decodes to a versioned RIPEMD-160 encoded hash using the flickr alphabet" do
    # ex per: https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
    assert "1omYBzBMizrQWWiQJzWwbeRMkSy7qKwtaS"
           |> B58.version_decode58_check!(alphabet: :flickr)
           |> :binary.decode_unsigned() == 0x0F54A5851E9372B87810A8E60CDD2E7CFD80B6E31
  end

  test "version_decode58_check!/2 handles binaries with invalid checksums encoded using the flickr alphabet" do
    # corrupt last byte
    assert_raise ArgumentError, fn ->
      B58.version_decode58_check!("12k5b5YQSE7VWB", alphabet: :flickr)
    end

    # corrupt first byte
    assert_raise ArgumentError, fn ->
      B58.version_decode58_check!("r5Nrh5Ytdpr9wWZNFRBvo", alphabet: :flickr)
    end

    # corrupt middle byte
    assert_raise ArgumentError, fn ->
      B58.version_decode58_check!("xwmKdxbrbevuUe2VpGp1MB", alphabet: :flickr)
    end

    # corrupted empty
    assert_raise ArgumentError, fn -> B58.version_decode58_check!("1v4AG", alphabet: :flickr) end
  end

  test "version_decode58_check/2 handles binaries with invalid checksums encoded using the flickr alphabet" do
    # corrupt last byte
    {:error, _} = B58.version_decode58_check("12k5b5YQSE7VWB", alphabet: :flickr)
    # corrupt first byte
    {:error, _} = B58.version_decode58_check("r5Nrh5Ytdpr9wWZNFRBvo", alphabet: :flickr)
    # corrupt middle byte
    {:error, _} = B58.version_decode58_check("xwmKdxbrbevuUe2VpGp1MB", alphabet: :flickr)
    # corrupted empty
    {:error, _} = B58.version_decode58_check("1v4AG", alphabet: :flickr)
  end

  test "version_decode58_check!/2 handles invalid binaries when using encoding using the flickr alphabet" do
    # Zero is not in this alphabet
    assert_raise ArgumentError, fn ->
      B58.version_decode58_check!("02k5b5YQSE7VWB", alphabet: :flickr)
    end

    # Underscore is not in this alphabet
    assert_raise ArgumentError, fn ->
      B58.version_decode58_check!("b5Nrh5Ytdpr9wWZNFRBvo_", alphabet: :flickr)
    end

    # Base64 alphabet is not compatible
    assert_raise ArgumentError, fn ->
      "Hello World"
      |> Base.encode64()
      |> B58.version_decode58_check!(alphabet: :flickr)
    end

    # missing bytes
    assert_raise ArgumentError, fn -> B58.version_decode58_check!("1v4AG", alphabet: :flickr) end
    assert_raise ArgumentError, fn -> B58.version_decode58_check!(<<>>, alphabet: :flickr) end
  end

  test "version_decode58_check/2 handles invalid binaries when using encoding using the flickr alphabet" do
    # Zero is not in this alphabet
    {:error, _} = B58.version_decode58_check("02k5b5YQSE7VWB", alphabet: :flickr)
    # Underscore is not in this alphabet
    {:error, _} = B58.version_decode58_check("b5Nrh5Ytdpr9wWZNFRBvo_", alphabet: :flickr)
    # Base64 alphabet is not compatible
    {:error, _} =
      "Hello World"
      |> Base.encode64()
      |> B58.version_decode58_check(alphabet: :flickr)

    # missing bytes
    {:error, _} = B58.version_decode58_check("1v4AG", alphabet: :flickr)
    {:error, _} = B58.version_decode58_check(<<>>, alphabet: :flickr)
  end

  # ============================================================================
  # Ripple
  # ============================================================================
  test "encode58/2 Base58 encodes strings according to the ripple alphabet" do
    assert B58.encode58("hello", alphabet: :ripple) == "U83eVZg"
    assert B58.encode58("hello world", alphabet: :ripple) == "StVrDLaUATiyKyV"
    assert B58.encode58("Hello World", alphabet: :ripple) == "JxErpTiA7PhnBMd"
    assert B58.encode58(<<>>, alphabet: :ripple) == <<>>
  end

  test "encode58/2 Base58 encodes sha-256 strings according to the ripple alphabet" do
    # From https://github.com/multiformats/multihash
    assert "12209CBC07C3F991725836A3AA2A581CA2029198AA420B9D99BC0E131D9F3E2CBE47"
           |> Base.decode16!()
           |> B58.encode58(alphabet: :ripple) == "QmYt7ch5TUbbCVSD4KvtQqiCyezPP8EvNssAEmutA9PBBk"
  end

  test "encode58/2 handles encodes leading zeroes for the ripple alphabet" do
    assert B58.encode58(<<0>>, alphabet: :ripple) == "r"
    assert B58.encode58(<<0, 0, 0, "hello world">>, alphabet: :ripple) == "rrrStVrDLaUATiyKyV"
    assert B58.encode58(<<0, 0, 0>>, alphabet: :ripple) == "rrr"
  end

  test "encode58_check!/3 accepts only unsigned single byte integers using the ripple alphabet" do
    assert B58.encode58_check!("a", <<0>>, alphabet: :ripple) == "rUst945b"
    assert B58.encode58_check!("a", 0, alphabet: :ripple) == "rUst945b"
    assert B58.encode58_check!("a", <<1>>, alphabet: :ripple) == "gqkAoXD"
    assert B58.encode58_check!("a", 1, alphabet: :ripple) == "gqkAoXD"
    assert B58.encode58_check!("a", <<2>>, alphabet: :ripple) == "pBkJb6jW"
    assert B58.encode58_check!("a", 2, alphabet: :ripple) == "pBkJb6jW"
    assert B58.encode58_check!("a", <<255>>, alphabet: :ripple) == "sUwAsRMUe"
    assert B58.encode58_check!("a", 255, alphabet: :ripple) == "sUwAsRMUe"
    assert B58.encode58_check!(<<>>, <<2>>, alphabet: :ripple) == "NF5sKP"
    assert B58.encode58_check!(<<>>, 2, alphabet: :ripple) == "NF5sKP"

    assert_raise ArgumentError, fn ->
      B58.encode58_check!("a", 256, alphabet: :ripple)
    end

    assert_raise ArgumentError, fn ->
      B58.encode58_check!("a", -1, alphabet: :ripple)
    end

    assert_raise ArgumentError, fn ->
      B58.encode58_check!("a", <<1, 0>>, alphabet: :ripple)
    end
  end

  test "encode58_check!/3 Base58Check encodes strings according to the ripple alphabet" do
    assert B58.encode58_check!("hello", 0, alphabet: :ripple) == "rpLnBnyq1CfvAb"
    assert B58.encode58_check!("hello world", 1, alphabet: :ripple) == "BnoSHny7DQS9XAzogicWP"
    assert B58.encode58_check!("Hello World", 255, alphabet: :ripple) == "YXMkDYBSTNWVuNpvQ6Qr8c"
    assert B58.encode58_check!(<<>>, 0, alphabet: :ripple) == "rW6hb6"
  end

  test "encode58_check/3 Base58Check encodes strings according to the ripple alphabet" do
    assert B58.encode58_check("hello", 0, alphabet: :ripple) == {:ok, "rpLnBnyq1CfvAb"}

    assert B58.encode58_check("hello world", 1, alphabet: :ripple) ==
             {:ok, "BnoSHny7DQS9XAzogicWP"}

    assert B58.encode58_check("Hello World", 255, alphabet: :ripple) ==
             {:ok, "YXMkDYBSTNWVuNpvQ6Qr8c"}

    assert B58.encode58_check(<<>>, 0, alphabet: :ripple) == {:ok, "rW6hb6"}
  end

  test "encode58_check!/3 Base58Check encodes sha-256 strings according to the ripple alphabet" do
    # From https://github.com/multiformats/multihash
    assert "12209CBC07C3F991725836A3AA2A581CA2029198AA420B9D99BC0E131D9F3E2CBE47"
           |> Base.decode16!()
           |> B58.encode58_check!(0, alphabet: :ripple) ==
             "rsgXk93a69FwFWsu4eGwHDq78YHo3croSCH2jVDuzPt5SokA6zzeK"
  end

  test "encode58_check!/3 Base58Check encodes a RIPEMD-160 hash using the ripple alphabet" do
    # ex per: https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
    assert "f54a5851e9372b87810a8e60cdd2e7cfd80b6e31"
           |> Base.decode16!(case: :lower)
           |> B58.encode58_check!(0, alphabet: :ripple) == "rPMyc2c8J2SqAAJqj2AXBNi8L1ZfRkX7w1"
  end

  test "encode58_check!/2 handles Base58 encoding leading zeroes using the ripple alphabet" do
    assert B58.encode58_check!(<<0>>, 0, alphabet: :ripple) == "rrpedBaq"

    assert B58.encode58_check!(<<0, 0, 0, "hello world">>, 0, alphabet: :ripple) ==
             "rrrrsvQBfBaMiGQZ2xUiokgxh"

    assert B58.encode58_check!(<<0, 0, 0>>, 0, alphabet: :ripple) == "rrrrhbdQd2"
  end

  test "version_encode58_check!/3 accepts unsigned single byte integer versions using the ripple alphabet" do
    assert B58.version_encode58_check!(<<0, "a">>, alphabet: :ripple) == "rUst945b"
    assert B58.version_encode58_check!(<<1, "a">>, alphabet: :ripple) == "gqkAoXD"
    assert B58.version_encode58_check!(<<2, "a">>, alphabet: :ripple) == "pBkJb6jW"
    assert B58.version_encode58_check!(<<255, "a">>, alphabet: :ripple) == "sUwAsRMUe"
    assert B58.version_encode58_check!(<<2>>, alphabet: :ripple) == "NF5sKP"
  end

  test "version_encode58_check/3 Base58Check encodes strings according to the ripple alphabet" do
    assert B58.version_encode58_check(<<0, "hello">>, alphabet: :ripple) ==
             {:ok, "rpLnBnyq1CfvAb"}

    assert B58.version_encode58_check(<<1, "hello world">>, alphabet: :ripple) ==
             {:ok, "BnoSHny7DQS9XAzogicWP"}

    assert B58.version_encode58_check(<<255, "Hello World">>, alphabet: :ripple) ==
             {:ok, "YXMkDYBSTNWVuNpvQ6Qr8c"}

    assert B58.version_encode58_check(<<0>>, alphabet: :ripple) == {:ok, "rW6hb6"}
  end

  test "version_encode58_check!/3 Base58Check encodes strings according to the ripple alphabet" do
    assert B58.version_encode58_check!(<<0, "hello">>, alphabet: :ripple) == "rpLnBnyq1CfvAb"

    assert B58.version_encode58_check!(<<1, "hello world">>, alphabet: :ripple) ==
             "BnoSHny7DQS9XAzogicWP"

    assert B58.version_encode58_check!(<<255, "Hello World">>, alphabet: :ripple) ==
             "YXMkDYBSTNWVuNpvQ6Qr8c"

    assert B58.version_encode58_check!(<<0>>, alphabet: :ripple) == "rW6hb6"
  end

  test "version_encode58_check!/2 Base58Check encodes a versioned RIPEMD-160 hash using the ripple alphabet" do
    # ex per: https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
    assert 0xF54A5851E9372B87810A8E60CDD2E7CFD80B6E31
           |> :binary.encode_unsigned()
           |> B58.version_binary(0)
           |> B58.version_encode58_check!(alphabet: :ripple) ==
             "rPMyc2c8J2SqAAJqj2AXBNi8L1ZfRkX7w1"
  end

  test "version_encode58_check!/2 handles Base58 encoding leading zeroes using the ripple alphabet" do
    assert B58.version_encode58_check!(<<0, 0>>, alphabet: :ripple) == "rrpedBaq"

    assert B58.version_encode58_check!(<<0, 0, 0, 0, "hello world">>, alphabet: :ripple) ==
             "rrrrsvQBfBaMiGQZ2xUiokgxh"

    assert B58.version_encode58_check!(<<0, 0, 0, 0>>, alphabet: :ripple) == "rrrrhbdQd2"
  end

  test "decode58!/2 decodes Base58 encoded binaries using the ripple alphabet" do
    assert B58.decode58!("U83eVZg", alphabet: :ripple) == "hello"
    assert B58.decode58!("StVrDLaUATiyKyV", alphabet: :ripple) == "hello world"
    assert B58.decode58!("JxErpTiA7PhnBMd", alphabet: :ripple) == "Hello World"
    assert B58.decode58!(<<>>, alphabet: :ripple) == <<>>
  end

  test "decode58!/2 handles Base58 encoded with leading zeroes using the ripple alphabet" do
    assert B58.decode58!("r", alphabet: :ripple) == <<0>>
    assert B58.decode58!("rrr", alphabet: :ripple) == <<0, 0, 0>>
    assert B58.decode58!("rrrStVrDLaUATiyKyV", alphabet: :ripple) == <<0, 0, 0, "hello world">>
  end

  test "decode58!/2 Base58 decodes sha-256 strings using the ripple alphabet" do
    # From https://github.com/multiformats/multihash
    assert "QmYt7ch5TUbbCVSD4KvtQqiCyezPP8EvNssAEmutA9PBBk"
           |> B58.decode58!(alphabet: :ripple)
           |> Base.encode16() ==
             "12209CBC07C3F991725836A3AA2A581CA2029198AA420B9D99BC0E131D9F3E2CBE47"
  end

  test "decode58!/2 Base58 handles invalid binaries when using the ripple alphabet" do
    # invalid character
    assert_raise ArgumentError, fn ->
      B58.decode58!("~", alphabet: :ripple)
    end

    # invalid leading character
    assert_raise ArgumentError, fn ->
      B58.decode58!("~U83eVZg", alphabet: :ripple)
    end

    # invalid trailing character
    assert_raise ArgumentError, fn ->
      B58.decode58!("U83eVZg^", alphabet: :ripple)
    end

    # invalid character mid string
    assert_raise ArgumentError, fn ->
      B58.decode58!("U83%VZg", alphabet: :ripple)
    end

    # invalid character excluded from alphabet due to clarity
    assert_raise ArgumentError, fn ->
      B58.decode58!("O83eVZg", alphabet: :ripple)
    end

    # base16 encoded string
    assert_raise ArgumentError, fn ->
      "12209CBC07C3F991725836A3AA2A581CA2029198AA420B9D99BC0E131D9F3E2CBE47"
      |> B58.decode58!(alphabet: :ripple)
    end
  end

  test "decode58/2 Base58 handles invalid binaries when using the ripple alphabet" do
    # invalid character
    {:error, _} = B58.decode58("~", alphabet: :ripple)
    # invalid leading character
    {:error, _} = B58.decode58("~U83eVZg", alphabet: :ripple)
    # invalid trailing character
    {:error, _} = B58.decode58("U83eVZg^", alphabet: :ripple)
    # invalid character mid string
    {:error, _} = B58.decode58("U83%VZ", alphabet: :ripple)
    # invalid character excluded from alphabet due to clarity
    {:error, _} = B58.decode58("O83eVZg", alphabet: :ripple)
    # base16 encoded string
    {:error, _} =
      "12209CBC07C3F991725836A3AA2A581CA2029198AA420B9D99BC0E131D9F3E2CBE47"
      |> B58.decode58(alphabet: :ripple)
  end

  test "decode58_check!/2 decodes Base58Check encoded binaries using the ripple alphabet" do
    assert B58.decode58_check!("rpLnBnyq1CfvAb", alphabet: :ripple) == {"hello", <<0>>}

    assert B58.decode58_check!("BnoSHny7DQS9XAzogicWP", alphabet: :ripple) ==
             {"hello world", <<1>>}

    assert B58.decode58_check!("YXMkDYBSTNWVuNpvQ6Qr8c", alphabet: :ripple) ==
             {"Hello World", <<255>>}

    assert B58.decode58_check!("rW6hb6", alphabet: :ripple) == {<<>>, <<0>>}
  end

  test "decode58_check/2 decodes Base58Check encoded binaries using the ripple alphabet" do
    assert B58.decode58_check("rpLnBnyq1CfvAb", alphabet: :ripple) == {:ok, {"hello", <<0>>}}

    assert B58.decode58_check("BnoSHny7DQS9XAzogicWP", alphabet: :ripple) ==
             {:ok, {"hello world", <<1>>}}

    assert B58.decode58_check("YXMkDYBSTNWVuNpvQ6Qr8c", alphabet: :ripple) ==
             {:ok, {"Hello World", <<255>>}}

    assert B58.decode58_check("rW6hb6", alphabet: :ripple) == {:ok, {<<>>, <<0>>}}
  end

  test "decode58_check!/2 Base58Check decodes to a RIPEMD-160 encoded hash using the ripple alphabet" do
    # ex per: https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
    {hash_bin, version} =
      "rPMyc2c8J2SqAAJqj2AXBNi8L1ZfRkX7w1"
      |> B58.decode58_check!(alphabet: :ripple)

    assert version == <<0>>

    assert hash_bin
           |> Base.encode16(case: :lower) == "f54a5851e9372b87810a8e60cdd2e7cfd80b6e31"
  end

  test "decode58_check!/2 handles binaries with invalid checksums encoded using the ripple alphabet" do
    # corrupt last byte
    assert_raise ArgumentError, fn -> B58.decode58_check!("1pLnBnyq1CfvAq", alphabet: :ripple) end
    # corrupt first byte
    assert_raise ArgumentError, fn -> B58.decode58_check!("2pLnBnyq1CfvAb", alphabet: :ripple) end
    # corrupt middle byte
    assert_raise ArgumentError, fn -> B58.decode58_check!("1pLnBnqq1CfvAb", alphabet: :ripple) end
    # corrupted empty
    assert_raise ArgumentError, fn -> B58.decode58_check!("1B6hb6", alphabet: :ripple) end
  end

  test "decode58_check/2 handles binaries with invalid checksums encoded using the ripple alphabet" do
    # corrupt last byte
    {:error, _} = B58.decode58_check("1pLnBnyq1CfvAq", alphabet: :ripple)
    # corrupt first byte
    {:error, _} = B58.decode58_check("2pLnBnyq1CfvAb", alphabet: :ripple)
    # corrupt middle byte
    {:error, _} = B58.decode58_check("1pLnBnqq1CfvAb", alphabet: :ripple)
    # corrupted empty
    {:error, _} = B58.decode58_check("1W6bb6", alphabet: :ripple)
  end

  test "decode58_check!/2 handles invalid binaries when using encoding using the ripple alphabet" do
    # Zero is not in this alphabet
    assert_raise ArgumentError, fn -> B58.decode58_check!("0pLnBnyq1CfvAb", alphabet: :ripple) end
    # Underscore is not in this alphabet
    assert_raise ArgumentError, fn ->
      B58.decode58_check!("1pLnBnyq1CfvAb_", alphabet: :ripple)
    end

    # Base64 alphabet is not compatible
    assert_raise ArgumentError, fn ->
      "Hello World"
      |> Base.encode64()
      |> B58.decode58_check!(alphabet: :ripple)
    end

    # missing bytes
    assert_raise ArgumentError, fn -> B58.decode58_check!("16hb6", alphabet: :ripple) end
    assert_raise ArgumentError, fn -> B58.decode58_check!(<<>>, alphabet: :ripple) end
  end

  test "decode58_check/2 handles invalid binaries when using encoding using the ripple alphabet" do
    # Zero is not in this alphabet
    {:error, _} = B58.decode58_check("0pLnBnyq1CfvAb", alphabet: :ripple)
    # Underscore is not in this alphabet
    {:error, _} = B58.decode58_check("1pLnBnyq1CfvAb_", alphabet: :ripple)
    # Base64 alphabet is not compatible
    {:error, _} =
      "Hello World"
      |> Base.encode64()
      |> B58.decode58_check(alphabet: :ripple)

    # missing bytes
    {:error, _} = B58.decode58_check("16hb6", alphabet: :ripple)
    {:error, _} = B58.decode58_check(<<>>, alphabet: :ripple)
  end

  test "version_decode58_check!/2 decodes Base58Check encoded binaries using the ripple alphabet" do
    assert B58.version_decode58_check!("rpLnBnyq1CfvAb", alphabet: :ripple) == <<0, "hello">>

    assert B58.version_decode58_check!("BnoSHny7DQS9XAzogicWP", alphabet: :ripple) ==
             <<1, "hello world">>

    assert B58.version_decode58_check!("YXMkDYBSTNWVuNpvQ6Qr8c", alphabet: :ripple) ==
             <<255, "Hello World">>

    assert B58.version_decode58_check!("rW6hb6", alphabet: :ripple) == <<0>>
  end

  test "version_decode58_check/2 decodes Base58Check encoded binaries using the ripple alphabet" do
    assert B58.version_decode58_check("rpLnBnyq1CfvAb", alphabet: :ripple) ==
             {:ok, <<0, "hello">>}

    assert B58.version_decode58_check("BnoSHny7DQS9XAzogicWP", alphabet: :ripple) ==
             {:ok, <<1, "hello world">>}

    assert B58.version_decode58_check("YXMkDYBSTNWVuNpvQ6Qr8c", alphabet: :ripple) ==
             {:ok, <<255, "Hello World">>}

    assert B58.version_decode58_check("rW6hb6", alphabet: :ripple) == {:ok, <<0>>}
  end

  test "version_decode58_check!/2 Base58Check decodes to a versioned RIPEMD-160 encoded hash using the ripple alphabet" do
    # ex per: https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
    assert "rPMyc2c8J2SqAAJqj2AXBNi8L1ZfRkX7w1"
           |> B58.version_decode58_check!(alphabet: :ripple)
           |> :binary.decode_unsigned() == 0x0F54A5851E9372B87810A8E60CDD2E7CFD80B6E31
  end

  test "version_decode58_check!/2 handles binaries with invalid checksums encoded using the ripple alphabet" do
    # corrupt last byte
    assert_raise ArgumentError, fn ->
      B58.version_decode58_check!("rpLnBnyq1CfvAv", alphabet: :ripple)
    end

    # corrupt first byte
    assert_raise ArgumentError, fn ->
      B58.version_decode58_check!("bpLnBnyq1CfvAb", alphabet: :ripple)
    end

    # corrupt middle byte
    assert_raise ArgumentError, fn ->
      B58.version_decode58_check!("rpLnBnqq1CfvAb", alphabet: :ripple)
    end

    # corrupted empty
    assert_raise ArgumentError, fn ->
      B58.version_decode58_check!("rW6bhb6", alphabet: :ripple)
    end
  end

  test "version_decode58_check/2 handles binaries with invalid checksums encoded using the ripple alphabet" do
    # corrupt last byte
    {:error, _} = B58.version_decode58_check("rpLnBnyq1CfvAv", alphabet: :ripple)
    # corrupt first byte
    {:error, _} = B58.version_decode58_check("bpLnBnyq1CfvAb", alphabet: :ripple)
    # corrupt middle byte
    {:error, _} = B58.version_decode58_check("rpLnBnqq1CfvAb", alphabet: :ripple)
    # corrupted empty
    {:error, _} = B58.version_decode58_check("rW6bhb6", alphabet: :ripple)
  end

  # You, friend, are a reader

  test "version_decode58_check!/2 handles invalid binaries when using encoding using the ripple alphabet" do
    # Zero is not in this alphabet
    assert_raise ArgumentError, fn ->
      B58.version_decode58_check!("0pLnBnyq1CfvAb", alphabet: :ripple)
    end

    # Underscore is not in this alphabet
    assert_raise ArgumentError, fn ->
      B58.version_decode58_check!("rpLnBnyq1CfvAb_", alphabet: :ripple)
    end

    # Base64 alphabet is not compatible
    assert_raise ArgumentError, fn ->
      "Hello World"
      |> Base.encode64()
      |> B58.version_decode58_check!(alphabet: :ripple)
    end

    # missing bytes
    assert_raise ArgumentError, fn -> B58.version_decode58_check!("r6hb6", alphabet: :ripple) end
    assert_raise ArgumentError, fn -> B58.version_decode58_check!(<<>>, alphabet: :ripple) end
  end

  test "version_decode58_check/2 handles invalid binaries when using encoding using the ripple alphabet" do
    # Zero is not in this alphabet
    {:error, _} = B58.version_decode58_check("0pLnBnyq1CfvAb", alphabet: :ripple)
    # Underscore is not in this alphabet
    {:error, _} = B58.version_decode58_check("rpLnBnyq1CfvAb_", alphabet: :ripple)
    # Base64 alphabet is not compatible
    {:error, _} =
      "Hello World"
      |> Base.encode64()
      |> B58.version_decode58_check(alphabet: :ripple)

    # missing bytes
    {:error, _} = B58.version_decode58_check("r6hb6", alphabet: :ripple)
    {:error, _} = B58.version_decode58_check(<<>>, alphabet: :ripple)
  end

  # ============================================================================
  # For the masses, but I prefer other albums
  # ============================================================================
  test "alphabets/0 returns the IDs of all the known current alphabets" do
    assert alphabets() == [:btc, :flickr, :ripple]
  end

  test "version_binary/1 versions a binary according to Base58 rules using an uint8" do
    assert B58.version_binary("a", <<0>>) == <<0, "a">>
    assert B58.version_binary("a", 0) == <<0, "a">>
    assert B58.version_binary("a", <<1>>) == <<1, "a">>
    assert B58.version_binary("a", 1) == <<1, "a">>
    assert B58.version_binary("a", <<255>>) == <<255, "a">>
    assert B58.version_binary("a", 255) == <<255, "a">>
    assert B58.version_binary(<<>>, <<2>>) == <<2>>
    assert B58.version_binary(<<>>, 2) == <<2>>

    assert_raise ArgumentError, fn ->
      B58.version_binary("a", 256)
    end

    assert_raise ArgumentError, fn ->
      B58.version_binary("a", -1)
    end

    assert_raise ArgumentError, fn ->
      B58.version_binary("a", <<1, 0>>)
    end
  end
end
