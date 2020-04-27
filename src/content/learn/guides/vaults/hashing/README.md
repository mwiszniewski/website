---
order: 5
title: Hashing
---

A hash function computes a fixed length digest of an arbitrary long message.

The ockam vault interface supports `ockam_vault_sha256` which computes the SHA256
digest of an input buffer. A SHA256 digest is always 256 bits or 32 bytes long.
The `OCKAM_VAULT_SHA256_DIGEST_LENGTH` variable is defined to 32, the length in
of the output digest.

Once we have an [initialized vault handle](../setup) of type `ockam_vault_t`, we can
call the `ockam_vault_sha256` function using this handle.

```c
ockam_error_t ockam_vault_sha256(ockam_vault_t* vault,
                                 const uint8_t* input,
                                 size_t         input_length,
                                 uint8_t*       digest,
                                 size_t         digest_size,
                                 size_t*        digest_length);
```

```c
char*  input        = "hello world";
size_t input_length = strlen(input);

const size_t digest_size         = OCKAM_VAULT_SHA256_DIGEST_LENGTH;
uint8_t      digest[digest_size] = { 0 };
size_t       digest_length;

error = ockam_vault_sha256(&vault, (uint8_t*) input, input_length, &digest[0], digest_size, &digest_length);
if (error) goto exit;

/* print the digest in hexadecimal form. */

int i;
for (i = 0; i < digest_size; i++) { printf("%02x", digest[i]); }
printf("\n");
```


### Complete Example

```c

#include "ockam/error.h"

#include "ockam/memory.h"
#include "ockam/memory/stdlib.h"

#include "ockam/vault.h"
#include "ockam/vault/default.h"

#include <stdio.h>

int main(void)
{
  int exit_code = 0;
  ockam_error_t error;


  /* initialize a handle to stdlib implementation of the memory interface */

  ockam_memory_t memory;

  error = ockam_memory_stdlib_init(&memory);
  if (error) goto exit;


  /* initialize a handle to the default software implementation of the vault interface */

  ockam_vault_t                    vault;
  ockam_vault_default_attributes_t vault_attributes = { .memory = &memory };

  error = ockam_vault_default_init(&vault, &vault_attributes);
  if (error) goto exit;


  /* use the vault to generate compute a digest */

  char*  input        = "hello world";
  size_t input_length = strlen(input);

  const size_t digest_size         = OCKAM_VAULT_SHA256_DIGEST_LENGTH;
  uint8_t      digest[digest_size] = { 0 };
  size_t       digest_length;

  error = ockam_vault_sha256(&vault, (uint8_t*) input, input_length, &digest[0], digest_size, &digest_length);
  if (error) goto exit;

  /* print the digest in hexadecimal form. */

  int i;
  for (i = 0; i < digest_size; i++) { printf("%02x", digest[i]); }
  printf("\n");


  /* cleanup */

  error = ockam_vault_deinit(&vault);
  if (error) goto exit;

  error = ockam_memory_deinit(&memory);

exit:
  if (error) exit_code = -1;
  return exit_code;
}
```
