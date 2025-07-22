# ERPNext Authentication Bypass and Server Side Template Injection
In this module, we discussed a methodology to discover vulnerabilities in applications. We uncovered a SQL injection vulnerability that led to administrator access to ERPNext.
With administrator access, we discovered a Server-Side Template Injection vulnerability that was blacklisting characters commonly used for exploitation. We devised a way to bypass the filter and execute commands against the system.
This clearly demonstrates the risk of unchecked user input passing through rendering functions.
