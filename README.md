## NAZO CTF Solver Tool

## Usage

```
tsx nazoutil.ts -h                                                  
usage: nazoutil.ts [-h] [--provider PROVIDER] [--contract CONTRACT] [--type {validate,submit}] [--challenge CHALLENGE] [--flag FLAG] [--private-key PRIVATE_KEY]

NAZO CTF Solver Tool

optional arguments:
  -h, --help            show this help message and exit
  --provider PROVIDER   Ethereum RPC provider
  --contract CONTRACT   CTF contract address
  --type {validate,submit}
                        validate or submit flag
  --challenge CHALLENGE
                        Challenge id
  --flag FLAG           flag to validate or submit
  --private-key PRIVATE_KEY

Want to get flag? see https://www.youtube.com/watch?v=dQw4w9WgXcQ
```

## Example


#### Validate flag

```
$ tsx nazoutil.ts --type validate --challenge [CHALLENGE_ID] --flag '[REDACTED]'
Challenge 2 is created by [ 0x829309B5b62192625D261F9B77ca9c15758A489a ] with score 10
[✅] flag is correct
```

#### Submit flag

```
$ tsx nazoutil.ts --type submit --challenge [CHALLENGE_ID] --flag '[REDACTED]'
[✅] Challenge 2 solved, got 10 NAZO
Total 2 solved
Transaction Hash: 0x826bc914000f898fd7ef9ed181e017522cd8bfb7999bbc0924e6ccb6f3bfd2ea
```