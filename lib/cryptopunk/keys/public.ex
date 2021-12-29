defmodule Cryptopunk.Keys.Public do
  defstruct [:key, :chain_code]

  @type t :: %__MODULE__{}

  def new(key, chain_code) do
    %__MODULE__{
      key: key,
      chain_code: chain_code
    }
  end
end
