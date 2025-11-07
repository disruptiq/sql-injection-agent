#!/usr/bin/env python3
"""
Entry point for the SQL Injection Agent
"""

from .scanner import main_cli
import logging

if __name__ == '__main__':
    try:
        main_cli()
    finally:
        logging.shutdown()
