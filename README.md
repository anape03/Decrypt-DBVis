# Decrypt-DBVis
Simple Tool to decrypt passwords from DbVisualizer.\
Original decryptor by [gerry](https://gist.github.com/gerry): [decrypt_dbvis.py](https://gist.github.com/gerry/c4602c23783d894b8d96)

Can be used to decrypt a single password, or every password in a configuration file.

## How to use

### Decrypt every password in configuration file:

`-f,-file <file-name>`

ex. 
```
> java DBVisDecrypt -f "C:\Users\userxxx\.dbvis\config233\dbvis.xml"
```

### Decrypt specific password:

`-p,-password <encrypted password>`

ex. 
```
> java DBVisDecrypt -p AK+fe8JpLKGWdqEyeDISWg==
```
