# SQLInjectionChecker

A simple SQL injection checker script

## How it works

```
// Returns true if suspicious patterns were detected in $_GET or $_POST, false otherwise

\DirkBaumeister\SQLInjectionChecker\Checker::detect()
```
```
// Return useful data about this incident if detect was true
// Params: true returns JSON format, false (or ommitted) returns array

\DirkBaumeister\SQLInjectionChecker\Checker::getSuspectData([true])
```
