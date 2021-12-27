defmodule Cryptopunk.DerivationPath do
  defstruct [:purpose, :coin_type, :account, :change, :address_index]

  @type t :: %__MODULE__{}

  @spec new(Keyword.t()) :: t()
  def new(opts) do
    purpose = Keyword.get(opts, :purpose, "m")
    change = Keyword.get(opts, :change, 0)

    coin_type = Keyword.fetch!(opts, :coin_type)
    account = Keyword.fetch!(opts, :account)
    address_index = Keyword.fetch!(opts, :address_index)

    %__MODULE__{
      purpose: purpose,
      change: change,
      coin_type: coin_type,
      account: account,
      address_index: address_index
    }
  end
end
