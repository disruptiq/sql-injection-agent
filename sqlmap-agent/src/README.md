# SQL Injection Agent - Source Code Structure

This directory contains the modularized source code for the SQL Injection Agent, refactored from the original monolithic `agent.py` file for better maintainability and development experience.

## Module Structure

### `config.py`
- Configuration loading and management
- CLI argument parsing
- Default values and environment variables

### `openapi.py`
- OpenAPI specification parsing
- Schema resolution and parameter handling
- Request body construction

### `sqlmap.py`
- SQLMap command construction
- Command execution with timeout handling
- Output parsing and injection detection

### `scanner.py`
- Main scanning orchestration logic
- Multi-port scanning implementation
- Session management and logging

### `utils.py`
- General utility functions
- String manipulation and validation
- Database name extraction

### `main.py`
- Application entry point
- Graceful shutdown handling

## Development Benefits

- **Modularity**: Each module has a single responsibility
- **Testability**: Individual components can be unit tested
- **Maintainability**: Easier to locate and modify specific functionality
- **Collaboration**: Multiple developers can work on different modules simultaneously

## Backward Compatibility

The original `agent.py` file remains as a compatibility wrapper that imports from `src.main`, ensuring existing usage continues to work.

## Adding New Features

When implementing new features:
1. Identify which module the feature belongs to
2. Add the functionality to the appropriate module
3. Update imports and dependencies as needed
4. Add tests for the new functionality
