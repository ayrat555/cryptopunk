defmodule Cryptopunk.Crypto.Ethereum.Validation do
  @moduledoc false

  @mixed_case_regexp ~r/^(0x)?[0-9a-f]{40}$/i
  @upcase_regexp ~r/^(0x|0X)?[0-9A-F]{40}$/
  @downcase_regexp ~r/^(0x|0X)?[0-9a-f]{40}$/

  @spec valid?(binary()) :: boolean()
  def valid?(address) do
    with true <- address_valid_format(address),
         true <- address_case_check(address) do
      true
    else
      _ -> check_address_checksum(address)
    end
  end

  # check if address meets basic requirements of an address
  defp address_valid_format(address), do: String.match?(address, @mixed_case_regexp)

  # check if address is all lowercase or uppercase
  defp address_case_check(address) do
    String.match?(address, @downcase_regexp) ||
      String.match?(address, @upcase_regexp)
  end

  # check each case of the address
  defp check_address_checksum("0x" <> address) do
    check_address_checksum(address)
  end

  defp check_address_checksum(address) do
    address_hash =
      address
      |> String.downcase()
      |> ExKeccak.hash_256()
      |> Base.encode16(case: :lower)

    0..39
    |> Enum.filter(fn index ->
      check_char(address, address_hash, index)
    end)
    |> case do
      [] -> true
      _ -> false
    end
  end

  defp check_char(address, address_hash, index) do
    {parsed_hash, _} =
      address_hash
      |> String.at(index)
      |> Integer.parse(16)

    address_element = String.at(address, index)
    upcase_check = parsed_hash > 7 && String.upcase(address_element) !== address_element
    downcase_check = parsed_hash <= 7 && String.downcase(address_element) !== address_element

    upcase_check || downcase_check
  end
end
