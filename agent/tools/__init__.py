from agent.tools.shell import execute_shell, SHELL_TOOL_SCHEMA
from agent.tools.file_read import read_file, FILE_READ_TOOL_SCHEMA

AVAILABLE_TOOLS = {
    "execute_shell": execute_shell,
    "read_file": read_file,
}
TOOL_SCHEMAS = [SHELL_TOOL_SCHEMA, FILE_READ_TOOL_SCHEMA]
