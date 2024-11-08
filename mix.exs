defmodule Cryptopunk.MixProject do
  use Mix.Project

  def project do
    [
      app: :cryptopunk,
      version: "0.7.7",
      elixir: "~> 1.12",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      description: "Hierarchical deterministic wallet (HD Wallet)",
      package: [
        maintainers: ["Ayrat Badykov"],
        licenses: ["MIT"],
        links: %{"GitHub" => "https://github.com/ayrat555/cryptopunk"}
      ]
    ]
  end

  def application do
    [
      extra_applications: [:logger, :crypto]
    ]
  end

  defp deps do
    [
      {:ex_keccak, "~> 0.7.5"},
      {:ex_pbkdf2, "~> 0.8.2"},
      {:ex_secp256k1, "~> 0.7.3"},
      {:ex_bech32, "~> 0.6.1"},
      {:ex_base58, "~> 0.6.2"},
      {:mnemoniac, "~> 0.1.3"},
      {:jason, "~> 1.4"},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.4", only: [:dev, :test], runtime: false},
      {:ex_doc, ">= 0.0.0", only: :dev, runtime: false}
    ]
  end
end
