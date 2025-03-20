import argparse
import asyncio
import logging
from . import server

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger('mcp_headless_gmail')

def main():
    logger.debug("Starting mcp-server-headless-gmail main()")
    parser = argparse.ArgumentParser(description='Headless Gmail MCP Server')
    args = parser.parse_args()
    
    # Run the async main function
    logger.debug("About to run server.main()")
    asyncio.run(server.main())
    logger.debug("Server main() completed")

if __name__ == "__main__":
    main()

# Expose important items at package level
__all__ = ["main", "server"] 