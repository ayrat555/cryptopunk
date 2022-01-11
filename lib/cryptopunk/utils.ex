defmodule Cryptopunk.Utils do
  @moduledoc """
  Utility functions
  """
  import Integer, only: [is_even: 1, is_odd: 1]

  alias Cryptopunk.Key

  def hmac_sha512(key, data) do
    :crypto.mac(:hmac, :sha512, key, data)
  end

  def ser_p(%Key{key: <<0x04::8, x::256, y::256>>, type: :public}) when is_even(y) do
    <<0x02::8, x::256>>
  end

  def ser_p(%Key{key: <<0x04::8, x::256, y::256>>, type: :public}) when is_odd(y) do
    <<0x03::8, x::256>>
  end
end
