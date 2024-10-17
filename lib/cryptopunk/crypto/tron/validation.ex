defmodule Cryptopunk.Crypto.Tron.Validation do
  @moduledoc false

  alias Cryptopunk.Crypto.Tron.ChecksumEncoding

  @mixed_case_regexp ~r/^T[A-Za-z1-9]{33}$/i
  @upcase_regexp ~r/^T[1-9A-Z]{33}$/
  @downcase_regexp ~r/^T[1-9a-f]{33}$/

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
