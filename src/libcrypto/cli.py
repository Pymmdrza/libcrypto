import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from typing import List, Optional

from . import __version__
from .wallet import Wallet, COIN_CONFIG
from .mnemonic import generate_mnemonic, validate_mnemonic

# Create a Typer application instance. This is the main entry point for commands.
app = typer.Typer(
    name="libcrypto",
    help="A professional library for Cryptography and Cryptocurrencies.",
    add_completion=False,
)

# Create a rich Console instance for beautiful output.
console = Console()


def version_callback(value: bool):
    """Callback function to display the version and exit."""
    if value:
        console.print(f"libcrypto version: [bold green]{__version__}[/bold green]")
        raise typer.Exit()


@app.callback()
def main(
        version: bool = typer.Option(
            None,
            "--version",
            "-v",
            help="Show the application's version and exit.",
            callback=version_callback,
            is_eager=True,
        )
):
    """
    LibCrypto CLI: Manage crypto keys, addresses, and mnemonics.
    """
    # This main function serves as a top-level entry point.
    # The 'version_callback' handles the --version flag.
    pass


@app.command()
def info():
    """
    Display information about the libcrypto package.
    """
    info_text = (
        f"[bold]libcrypto v{__version__}[/bold]\n"
        "[dim]A professional library for Cryptography and Cryptocurrencies in Python.[/dim]\n\n"
        "Author: [link=https://mmdrza.com][cyan]Mmdrza[/cyan][/link]\n"
        "Repository: [link=https://github.com/Pymmdrza/libcrypto]https://github.com/Pymmdrza/libcrypto[/link]"
    )
    panel = Panel(info_text, title="Package Information", border_style="blue", expand=False)
    console.print(panel)


@app.command()
def generate(
        private_key: Optional[str] = typer.Option(
            None,
            "--private-key",
            "-p",
            help="Generate addresses from an existing private key (WIF or Hex).",
        ),
        coins: List[str] = typer.Option(
            ["bitcoin", "ethereum", "tron", "ripple", "litecoin", "dogecoin", "dash", "bitcoin_cash"],
            "--coin",
            "-c",
            help="Specify coin(s) to generate addresses for. Can be used multiple times.",
        ),
):
    """
    Generate a new wallet or derive addresses from an existing private key.
    """
    try:
        if private_key:
            wallet = Wallet(private_key)
            console.print(Panel("Addresses derived from your provided private key",
                                title="[bold yellow]Wallet Details[/bold yellow]", border_style="yellow"))
        else:
            wallet = Wallet.generate()
            console.print(Panel("A new secure wallet has been generated for you!",
                                title="[bold green]New Wallet Created[/bold green]", border_style="green"))

        # --- Display Keys ---
        key_table = Table(title="Crypto Wallet Detail", show_header=False, box=None)
        key_table.add_column("Attribute", style="cyan")
        key_table.add_column("Value", style="white")

        key_table.add_row("Private Key (Hex)", wallet.private_key.hex)
        key_table.add_row("Private Key (WIF)", wallet.private_key.to_wif())
        key_table.add_row("Public Key (Compressed)", wallet._public_key_compressed.hex)
        key_table.add_row("Public Key (Uncompressed)", wallet._public_key_uncompressed.hex)
        console.print(key_table)

        # --- Display Addresses ---
        address_table = Table(title="Generated Addresses", box=None)
        address_table.add_column("Coin", style="bold magenta")
        address_table.add_column("Address Type", style="yellow")
        address_table.add_column("Address", style="bold green")

        for coin in coins:
            coin = coin.lower()
            if coin not in COIN_CONFIG:
                console.print(f"[bold red]Error:[/] Unsupported coin '{coin}'. Skipping.")
                continue

            addresses = wallet.get_all_addresses(coin)
            for addr_type, address in addresses.items():
                address_table.add_row(coin.capitalize(), addr_type, address)

        console.print(address_table)

    except Exception as e:
        console.print(f"[bold red]An error occurred:[/] {e}")
        raise typer.Exit(code=1)


# --- Mnemonic Sub-Commands ---
mnemonic_app = typer.Typer(name="mnemonic", help="Generate and validate BIP39 mnemonic phrases.")
app.add_typer(mnemonic_app, name="mnemonic")


@mnemonic_app.command("generate")
def mnemonic_generate(
        word_count: int = typer.Option(12, "--words", "-w",
                                       help="Number of words for the mnemonic (12, 15, 18, 21, or 24).")
):
    """
    Generate a new BIP39 mnemonic phrase.
    """
    try:
        mnemonic = generate_mnemonic(word_count)
        console.print(
            Panel(f"[bold cyan]{mnemonic}[/bold cyan]", title="Generated Mnemonic Phrase", border_style="green"))
    except ValueError as e:
        console.print(f"[bold red]Error:[/] {e}")


@mnemonic_app.command("validate")
def mnemonic_validate(
        phrase: str = typer.Argument(..., help="The mnemonic phrase to validate, enclosed in quotes.")
):
    """
    Validate a BIP39 mnemonic phrase.
    """
    is_valid = validate_mnemonic(phrase)
    if is_valid:
        console.print(Panel("[bold green]This mnemonic phrase is valid.[/bold green]", title="Validation Success",
                            border_style="green"))
    else:
        console.print(Panel("[bold red]This mnemonic phrase is invalid.[/bold red]", title="Validation Failed",
                            border_style="red"))
