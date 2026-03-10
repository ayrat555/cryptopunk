defmodule Cryptopunk.Derivation.Path do
  @moduledoc """
  Utility functions to work with deriviation path

  See https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki
  """
  defstruct [:type, :purpose, :coin_type, :account, :change, :address_index]

  @type t :: %__MODULE__{
          type: :private | :public,
          purpose: non_neg_integer(),
          change: non_neg_integer(),
          coin_type: non_neg_integer(),
          account: non_neg_integer(),
          address_index: non_neg_integer()
        }

  @type raw_path :: {atom(), [non_neg_integer]}

  @two_power_31 2_147_483_648

  defguard is_hardened(x) when is_integer(x) and x >= @two_power_31
  defguard is_normal(x) when is_integer(x) and x >= 0 and x < @two_power_31

  @spec new(Keyword.t()) :: t()
  def new(opts) do
    type = Keyword.get(opts, :type, :private)
    purpose = Keyword.get(opts, :purpose, 44)
    change = Keyword.get(opts, :change, 0)

    coin_type = Keyword.fetch!(opts, :coin_type)
    account = Keyword.fetch!(opts, :account)
    address_index = Keyword.fetch!(opts, :address_index)

    %__MODULE__{
      type: type,
      purpose: purpose,
      change: change,
      coin_type: coin_type,
      account: account,
      address_index: address_index
    }
  end

  @spec parse(String.t()) :: {:error, any()} | {:ok, t()}
  def parse(string_path) do
    string_path
    |> split_string_path()
    |> do_parse()
  end

  @spec to_raw_path(t()) :: raw_path()
  def to_raw_path(%__MODULE__{
        type: type,
        purpose: purpose,
        coin_type: coin_type,
        account: account,
        change: change,
        address_index: address_index
      }) do
    {type,
     [
       purpose + @two_power_31,
       coin_type + @two_power_31,
       account + @two_power_31,
       change,
       address_index
     ]}
  end

  @spec parse_incomplete_path(String.t()) :: {:ok, raw_path()} | {:error, any()}
  def parse_incomplete_path(string_path) do
    with [string_type | levels] <- split_string_path(string_path),
         {:ok, type} <- parse_type(string_type),
         {:ok, parsed_levels} <- parse_levels(levels) do
      {:ok, {type, parsed_levels}}
    end
  end

  @spec two_power_31() :: non_neg_integer()
  def two_power_31, do: @two_power_31

  defp do_parse([type, purpose, coin_type, account, change, address_index]) do
    with {:ok, type} <- parse_type(type),
         {:ok, purpose} <- parse_level(purpose, type: :purpose, hardened: true),
         {:ok, coin_type} <- parse_level(coin_type, type: :coin_type, hardened: true),
         {:ok, account} <- parse_level(account, type: :account, hardened: true),
         {:ok, change} <- parse_level(change, type: :change),
         {:ok, address_index} <- parse_level(address_index, type: :address_index) do
      params = [
        type: type,
        purpose: purpose,
        coin_type: coin_type,
        account: account,
        change: change,
        address_index: address_index
      ]

      {:ok, new(params)}
    end
  end

  defp do_parse(_other), do: {:error, :invalid_path}

  defp parse_type(type) do
    case type do
      "m" -> {:ok, :private}
      "M" -> {:ok, :public}
      _ -> {:error, {:invalid_level, :type}}
    end
  end

  defp parse_level(int, type: type, hardened: true) do
    case Integer.parse(int) do
      {num, "'"} -> {:ok, num}
      _ -> {:error, {:invalid_level, type}}
    end
  end

  defp parse_level(int, type: type) do
    case Integer.parse(int) do
      {num, ""} -> {:ok, num}
      _ -> {:error, {:invalid_level, type}}
    end
  end

  defp parse_level_with_type(int) do
    case Integer.parse(int) do
      {num, ""} -> {:ok, num}
      {num, "'"} -> {:ok, num + @two_power_31}
      result -> {:error, {:invalid_path_level, result}}
    end
  end

  defp split_string_path(string_path) do
    string_path
    |> String.split("/")
    |> Enum.map(&String.trim/1)
  end

  defp parse_levels(levels, acc \\ [])

  defp parse_levels([], acc) do
    {:ok, Enum.reverse(acc)}
  end

  defp parse_levels([level | tail], acc) do
    case parse_level_with_type(level) do
      {:ok, parsed_level} -> parse_levels(tail, [parsed_level | acc])
      error -> error
    end
  end
end
