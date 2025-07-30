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

## Vulnerability Discovery
To effectively review source code for vulnerabilities, we can search for dangerous functions, known as sinks. Once identified, we trace these functions back to their input sources. If the source input is controllable and no security controls exist along the data flow, the dangerous function may be exploitable.

In this Learning Unit, we will search the Dolibarr source code for dangerous functions and analyze any protective mechanisms that might impede exploitation.

### Dolibarr Source Code Analysis

If we're searching for sinks, we need to have a list of dangerous functions relevant to the programming language of our application. Since Dolibarr is a PHP application, we could start by searching for functions like `exec()`, `passthru()`, `system()`, or `shell_exec()`. These functions execute external commands or programs. If the application passes unsanitized user-input to these functions, we might be able to perform command injection attacks against the application.

The `eval()` function executed the contents of the string and displayed the results. While this example is benign, suppose we could modify the string an application passes to the `eval()` function. If the application lacked any input validation, we might be able to run arbitrary PHP code and take control of the server. This functions is difficult for developers to secure.

To search for potential security risks, we look for uses of `eval()` by typing `eval(` in the code-server *Search*. This returns `276` results across `101` files, including some unrelated uses like `dol_eval()`. To narrow the focus, we refine the search by adding a *leading space*, helping isolate direct uses of `eval()`.

We've reduced the number of results to `31` instances in `14` files. This is a more manageable number of files to review. Let's check the second result at `htdocs/core/lib/functions.lib.php`.

**The first two results** are from comments documenting the `dol_eval()` function, which starts on line `8943`.

```php
8943  /**
8944  * Replace eval function to add more security.
8945  * This function is called by verifCond() or trans() and transnoentitiesnoconv().
8946  *
8947  * @param 	string	$s					String to evaluate
8948  * @param	int		$returnvalue		0=No return (used to execute eval($a=something)). 1=Value of eval is returned (used to eval($something)).
8949  * @param   int     $hideerrors     	1=Hide errors
8950  * @param	string	$onlysimplestring	'0' (used for computed property of extrafields)=Accept all chars, '1' (most common use)=Accept only simple string with char 'a-z0-9\s^$_+-.*>&|=!?():"\',/@';',  '2' (not used)=Accept also ';[]'
8951  * @return	mixed						Nothing or return result of eval
8952  */
8953  function dol_eval($s, $returnvalue = 0, $hideerrors = 1, $onlysimplestring = '1')
```

The documentation indicates that `dol_eval()` is intended as a secure alternative to `eval()`, using the `$onlysimplestring` variable to control allowed characters. To assess its safety, we need to examine how this check is implemented and whether other protections are in place.

Notably, **the third search result** appears within the `dol_eval()` function itself, which includes four calls to `eval()` between lines `9053` and `9061`. These lines should be closely reviewed to evaluate the function’s overall security.

```php
9051  if ($returnvalue) {
9052      if ($hideerrors) {
9053          return @eval('return '.$s.';');
9054      } else {
9055          return eval('return '.$s.';');
9056      }
9057  } else {
9058      if ($hideerrors) {
9059          @eval($s);
9060      } else {
9061          eval($s);
9062      }
9063  }
```
