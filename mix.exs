defmodule Cryptopunk.MixProject do
  use Mix.Project

  def project do
    [
      app: :cryptopunk,
      version: "0.1.0",
      elixir: "~> 1.12",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      description: "Placeholder for now",
      package: [
        maintainers: ["Ayrat Badykov"],
        licenses: ["MIT"],
        links: %{"GitHub" => "https://github.com/ayrat555/cryptopunk"}
      ]
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger, :crypto]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:basefiftyeight, "~> 0.1.0", github: "ulissesalmeida/b58", branch: "remove-prefix"},
      {:ex_keccak, "~> 0.3"},
      {:ex_pbkdf2, "~> 0.3"},
      {:ex_secp256k1, "~> 0.3"},
      {:jason, "~> 1.3"},
      {:credo, "~> 1.6", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.0", only: [:dev], runtime: false},
      {:ex_doc, ">= 0.0.0", only: :dev, runtime: false}
    ]
  end
end
