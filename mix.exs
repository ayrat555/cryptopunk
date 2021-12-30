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
      {:ex_pbkdf2, "~> 0.3"},
      {:ex_secp256k1, git: "https://github.com/ayrat555/ex_secp256k1", branch: "add"},
      {:ex_doc, ">= 0.0.0", only: :dev, runtime: false},
      {:jason, "~> 1.2"}
    ]
  end
end
