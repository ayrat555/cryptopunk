defmodule Cryptopunk.Seed do
  @opts %{alg: "sha512", iterations: 2048, length: 64, format: false}

  @spec create(String.t(), String.t()) :: binary()
  def create(mnemonic, pass \\ "") do
    opts = Map.put(@opts, :salt, "mnemonic" <> pass)

    ExPBKDF2.pbkdf2(mnemonic, opts)
  end
end
