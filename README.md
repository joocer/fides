**fides**  
secret scanning github action

----

Searches through code for looking for secrets, this is used to finding secrets 
which have been committed accidently.

Leveraging the powerful [YARA](https://yara.readthedocs.io/en/v4.1.1/index.html)
language, used by security professionals and malware analysts around the world to
build malware detection and classification tools.

## Example Usage
~~~
name:secret_scanner
on: [push, pull_request]
jobs:
  fides:
    runs-on: ubuntu-latest
    steps:
      - name: check out
        uses: actions/checkout@v2

      - name: execute_action
        uses: joocer/fides@main
~~~
