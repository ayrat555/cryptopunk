defmodule Cryptopunk.MixProject do
  use Mix.Project

  def project do
    [
      app: :cryptopunk,
      version: "0.6.7",
      elixir: "~> 1.10",
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
      {:ex_keccak, "~> 0.6"},
      {:ex_pbkdf2, "~> 0.8"},
      {:ex_secp256k1, "~> 0.7"},
      {:ex_bech32, "~> 0.4"},
      {:ex_base58, "~> 0.5"},
      {:mnemoniac, "~> 0.1.0"},
      {:jason, "~> 1.3"},
      {:credo, "~> 1.6", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.0", only: [:dev, :test], runtime: false},
      {:ex_doc, ">= 0.0.0", only: :dev, runtime: false}
    ]
  end
end
