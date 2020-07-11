defmodule Agora.MixProject do
  use Mix.Project

  def project do
    [
      app: :agora,
      version: "0.1.0",
      elixir: "~> 1.10",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      description: description(),
      package: package(),
      name: "Agora",
      source_url: "https://github.com/nathanjohnson320/agora"
    ]
  end

  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp deps do
    [{:ex_doc, "~> 0.21", only: :dev, runtime: false}]
  end

  defp description() do
    "Implementation of agora SDK's token signing for Access Keys"
  end

  defp package() do
    [
      licenses: ["MIT"],
      links: %{"GitHub" => "https://github.com/nathanjohnson320/agora"}
    ]
  end
end
