# Dolibarr Eval Filter Bypass RCE
This module reviews the source code of Dolibarr, an open-source **PHP-based** ERP and CRM application. It demonstrates how user input is passed to a dangerous function and how to exploit it for remote code execution (RCE), bypassing server-side validation. **The attack is performed with administrative privileges**, emphasizing the mindset required to analyze and defeat backend protections.
## Overview of Dangerous Functions
When we are analyzing source code, we should pay attention to dangerous functions that can lead to serious vulnerabilities. If an application passes user-supplied input to these functions, we may be able to craft malicious input to exploit them. The impact of these vulnerabilities depends on the actions the application performs and how much we know about the target application and its environment. However, most result in some form of remote code execution.
### PHP Dangerous Functions 
These functions can be exploited if user input is not properly sanitized. Avoid using them when possible, or apply strict validation and escaping.
#### Command Execution Functions

These execute system-level commands, which can lead to **Remote Code Execution (RCE) if misused**.

| Function        | Description                                                                 |
| --------------- | --------------------------------------------------------------------------- |
| `exec()`        | Executes a command and returns the last line of the output                  |
| `passthru()`    | Executes a command and outputs the raw result directly to the browser       |
| `system()`      | Executes a command, returns the last line, and outputs the result           |
| `shell_exec()`  | Executes a command and returns the complete output as a string              |
| `` `command` `` | Backtick operator, same as `shell_exec()` (only works on Unix-like systems) |
| `popen()`       | Opens a pipe to a process for reading/writing                               |
| `proc_open()`   | Opens a process with more control over input/output streams                 |
| `pcntl_exec()`  | Executes a program, replacing the current process                           |

#### Code Execution Functions
These evaluate PHP code dynamically, which can lead to **arbitrary code execution**.

| Function                         | Description                                                                          |
| -------------------------------- | ------------------------------------------------------------------------------------ |
| `eval()`                         | Evaluates a string as PHP code                                                       |
| `assert()`                       | Acts like `eval()` when used with a string                                           |
| `preg_replace('/pattern/e',...)` | The `/e` modifier evaluates replacement string as PHP code (deprecated)              |
| `create_function()`              | Dynamically creates an anonymous function (deprecated in PHP 7.2+)                   |
| `call_user_func()`               | Calls a user-defined function (can be dangerous if function name is user-controlled) |
| `call_user_func_array()`         | Calls a callback with parameters from an array (same risk as above)                  |

