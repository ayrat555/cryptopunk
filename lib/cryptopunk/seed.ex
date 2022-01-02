defmodule Cryptopunk.Seed do
  @opts %{alg: "sha512", iterations: 2048, length: 64, format: false}

  @spec create(String.t(), binary()) :: binary() | no_return()
  def create(mnemonic, pass \\ "") do
    opts = Map.put(@opts, :salt, "mnemonic" <> pass)

    ExPBKDF2.pbkdf2(mnemonic, opts)
  end
end
