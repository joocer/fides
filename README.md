**fides**  
secret scanning github action

----

Searches through code for looking for secrets, this is used to finding secrets 
which have been committed accidently.

Leveraging the powerful [YARA](https://yara.readthedocs.io/en/v4.1.1/index.html)
language, used by security professionals and malware analysts around the world to
build malware detection and classification tools.

## Example Usage
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fjoocer%2Ffides.svg?type=shield)](https://app.fossa.com/projects/git%2Bgithub.com%2Fjoocer%2Ffides?ref=badge_shield)

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

## Example Output
<img src="result-screen.png" width="1206px"/>

## License
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fjoocer%2Ffides.svg?type=large)](https://app.fossa.com/projects/git%2Bgithub.com%2Fjoocer%2Ffides?ref=badge_large)