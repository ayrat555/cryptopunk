defmodule Cryptopunk.Utils do
  def hmac_sha512(key, data) do
    :crypto.mac(:hmac, :sha512, key, data)
  end
end
