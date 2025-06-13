from .server import main_cli


def main():
    """MCP Uyuni Server"""
    import asyncio

    asyncio.run(main_cli())


if __name__ == "__main__":
    main()