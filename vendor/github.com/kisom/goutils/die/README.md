Simple fatal utilities for Go programs.

```
	result, err := doSomething()
	die.If(err)

	ok := processResult(result)
	if !ok {
		die.With("failed to process result %s", result.Name)
	}
```

