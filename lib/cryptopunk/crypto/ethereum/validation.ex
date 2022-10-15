defmodule Cryptopunk.Crypto.Ethereum.Validation do
  @moduledoc false

  alias Cryptopunk.Crypto.Ethereum.ChecksumEncoding

  @mixed_case_regexp ~r/^(0x)?[0-9a-f]{40}$/i
  @upcase_regexp ~r/^(0x|0X)?[0-9A-F]{40}$/
  @downcase_regexp ~r/^(0x|0X)?[0-9a-f]{40}$/

  @spec valid?(String.t()) :: boolean()
  def valid?(address) do
    with true <- address_valid_format(address),
         true <- address_case_check(address) do
      true
    else
      _ -> ChecksumEncoding.valid?(address)
    end
  end

  # check if address meets basic requirements of an address
  defp address_valid_format(address), do: String.match?(address, @mixed_case_regexp)

  # check if address is all lowercase or uppercase
  defp address_case_check(address) do
    String.match?(address, @downcase_regexp) ||
      String.match?(address, @upcase_regexp)
  end
end
