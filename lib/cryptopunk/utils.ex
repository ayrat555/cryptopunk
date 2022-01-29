defmodule Cryptopunk.Utils do
  @moduledoc """
  Utility functions
  """

  alias Cryptopunk.Key

  def hmac_sha512(key, data) do
    :crypto.mac(:hmac, :sha512, key, data)
  end

  def ser_p(%Key{key: key, type: :public}) do
    {:ok, compressed} = ExSecp256k1.public_key_compress(key)

    compressed
  end
end
