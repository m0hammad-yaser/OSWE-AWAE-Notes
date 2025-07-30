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
Each call to `eval()` includes the `$s` variable. Based on the function documentation, this variable contains the string to evaluate.

Now that we know the `dol_eval()` function calls `eval()`, let's review how many places in the application call this function. We'll search for `dol_eval(` in code-server *Search*.

Our search discovered `131` results in `56` files. It's reasonable for us to conclude that this application uses this function. We'll need to further analyze this function to determine if it presents a security risk.

### Understanding the Filter Conditions
According to the `dol_eval()` function documentation, the `$onlysimplestring` variable determines which characters the function allows. Let's review that implementation, which starts on line `8969`.

```php
8968  // Test on dangerous char (used for RCE), we allow only characters to make PHP variable testing
8969  if ($onlysimplestring == '1') {
8970      // We must accept: '1 && getDolGlobalInt("doesnotexist1") && $conf->global->MAIN_FEATURES_LEVEL'
8971      // We must accept: '$conf->barcode->enabled || preg_match(\'/^AAA/\',$leftmenu)'
8972      // We must accept: '$user->rights->cabinetmed->read && !$object->canvas=="patient@cabinetmed"'
8973      if (preg_match('/[^a-z0-9\s'.preg_quote('^$_+-.*>&|=!?():"\',/@', '/').']/i', $s)) {
8974          if ($returnvalue) {
8975              return 'Bad string syntax to evaluate (found chars that are not chars for simplestring): '.$s;
8976          } else {
8977              dol_syslog('Bad string syntax to evaluate (found chars that are not chars for simplestring): '.$s);
8978              return '';
8979          }
8980          // TODO
8981          // We can exclude all parenthesis ( that are not '($db' and 'getDolGlobalInt(' and 'getDolGlobalString(' and 'preg_match(' and 'isModEnabled('
8982          // ...
8983      }
8984  } elseif ($onlysimplestring == '2') {
8985      // We must accept: (($reloadedobj = new Task($db)) && ($reloadedobj->fetchNoCompute($object->id) > 0) && ($secondloadedobj = new Project($db)) && ($secondloadedobj->fetchNoCompute($reloadedobj->fk_project) > 0)) ? $secondloadedobj->ref : "Parent project not found"
8986      if (preg_match('/[^a-z0-9\s'.preg_quote('^$_+-.*>&|=!?():"\',/@;[]', '/').']/i', $s)) {
8987          if ($returnvalue) {
8988              return 'Bad string syntax to evaluate (found chars that are not chars for simplestring): '.$s;
8989          } else {
8990              dol_syslog('Bad string syntax to evaluate (found chars that are not chars for simplestring): '.$s);
8991              return '';
8992          }
8993      }
8994  }
```
Code excerpt from `functions.lib.php`

The `dol_eval()` function includes input validation based on the `$onlysimplestring` variable, but this control is limited. Specifically:
- It only applies restrictions if `$onlysimplestring` is set to `1` or `2` (checked on lines `8969` and `8984`).
- If `$onlysimplestring` has any other value, no input validation is enforced, potentially allowing unsafe characters.
- Although the function defaults `$onlysimplestring` to `1`, there is no fallback or guard clause to handle unexpected values.

The function uses regular expressions to filter the `$s` input:
- When `$onlysimplestring == 1`: a stricter regex applies.
- When `$onlysimplestring == 2`: the regex is slightly relaxed, allowing square brackets ([ and ]).

Next, we’ll review the checks implemented between lines `8995` and `9021` for additional validation or controls.

```php
8995  if (is_array($s) || $s === 'Array') {
8996      return 'Bad string syntax to evaluate (value is Array) '.var_export($s, true);
8997  }
8998  if (strpos($s, '::') !== false) {
8999      if ($returnvalue) {
9000          return 'Bad string syntax to evaluate (double : char is forbidden): '.$s;
9001      } else {
9002          dol_syslog('Bad string syntax to evaluate (double : char is forbidden): '.$s);
9003          return '';
9004      }
9005  }
9006  if (strpos($s, '`') !== false) {
9007      if ($returnvalue) {
9008          return 'Bad string syntax to evaluate (backtick char is forbidden): '.$s;
9009      } else {
9010          dol_syslog('Bad string syntax to evaluate (backtick char is forbidden): '.$s);
9011          return '';
9012      }
9013  }
9014  if (preg_match('/[^0-9]+\.[^0-9]+/', $s)) {	// We refuse . if not between 2 numbers
9015      if ($returnvalue) {
9016          return 'Bad string syntax to evaluate (dot char is forbidden): '.$s;
9017      } else {
9018          dol_syslog('Bad string syntax to evaluate (dot char is forbidden): '.$s);
9019          return '';
9020      }
9021  }
```
Code excerpt from `functions.lib.php`

